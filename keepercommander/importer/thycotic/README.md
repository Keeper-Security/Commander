# Commander support for Thycotic (Delinea) Secret Server

Commander supports importing secrets from Thycotic Secret Server (now known as Delinea Secret Server) into Keeper, with advanced features for permissions, team management, and user provisioning.

## Features

- **Restricted Secrets Support**: Automatically handles restricted secrets that require checkout permissions
- **User Migration**: Optional user provisioning from Thycotic to Keeper enterprise
- **Team Creation and Assignment**: Create Keeper teams and assign users from Thycotic groups
- **Secret-Level Permissions**: Map Thycotic secret permissions to Keeper shared records with full permission mapping
- **Selective Import**: Choose specific folders to import or import all secrets
- **Interactive Folder Selection**: Browse and select folders interactively during import
- **Bulk Permission Loading**: Efficient loading of secret permissions with worker pool for parallel processing
- **Rate Limit Handling**: Automatic retry on rate limits (HTTP 429) with exponential backoff
- **Error Handling**: Comprehensive error reporting and skipped records summary
- **Group Lookup**: Handles missing groups and complex group hierarchies

## Installation

Install Commander from the [repository root README](../../../README.md#linux--python-using-pip) (pip package or source with `requirements.txt`).

## Starting Commander

Commands below are run from the **Keeper Commander interactive shell**, not from your OS shell directly.

1. Install and log in to Commander (see [Starting Commander](../../../README.md#starting-commander)).
2. Launch the shell:

```bash
keeper shell
```

3. At the vault prompt (for example `My Vault>`), run `import`, `download-membership`, and related commands.

For a list of all Commander commands: `keeper help`.

## Environment variables (optional)

You can pre-set Delinea connection details instead of typing them at prompts. Environment variables are used when the import command does not supply a URL or when `download-membership` / other Thycotic plugins connect without inline credentials:

| Variable | Description |
|----------|-------------|
| `KEEPER_THYCOTIC_URL` | Secret Server base URL or tenant (for example `https://tenant.secretservercloud.com/` or `tenant`) |
| `KEEPER_THYCOTIC_USER` | Delinea username |
| `KEEPER_THYCOTIC_PASSWORD` | Delinea password |

If variables are unset, Commander prompts for URL, username, and password. Two-factor authentication still prompts interactively for a **Time-based One-Time Password (TOTP)** code when required.

## Usage

### Basic Import

Import all secrets from Thycotic Secret Server:

```bash
My Vault> import --format=thycotic https://<tenant>.secretservercloud.com
```

This will prompt for:

- **Username**: Your Thycotic username (unless `KEEPER_THYCOTIC_USER` is set)
- **Password**: Your Thycotic password (unless `KEEPER_THYCOTIC_PASSWORD` is set)
- **TOTP code**: If two-factor authentication is enabled

### Import Specific Folders

Import secrets from **one** folder, matched by **folder name** (case-insensitive). This flag does not accept a comma-separated list of multiple folders.

```bash
My Vault> import --format=thycotic --filter-folder=finance https://<tenant>.secretservercloud.com
```

Use [interactive folder selection](#interactive-folder-selection) or run separate imports if you need multiple folders.

### Interactive Folder Selection

Browse and select folders interactively:

```bash
My Vault> import --format=thycotic https://<tenant>.secretservercloud.com
# Then choose folders from the interactive menu
```

### Import with User Migration

Provision Thycotic users as Keeper enterprise users before importing secrets:

```bash
My Vault> import --format=thycotic --add-users https://<tenant>.secretservercloud.com
```

**Dry run**: Preview users to be created without creating them. This step only lists users; it does **not** read secret values and does **not** perform Delinea checkout.

```bash
My Vault> import --format=thycotic --add-users --dry-run https://<tenant>.secretservercloud.com
```

### Import with Team Creation

Create Keeper teams based on Thycotic groups and assign users:

```bash
My Vault> import --format=thycotic --add-users --add-teams https://<tenant>.secretservercloud.com
```

**Dry run**: Preview teams and user assignments without creating them:

```bash
My Vault> import --format=thycotic --add-users --add-teams --dry-run https://<tenant>.secretservercloud.com
```

### Import with Secret-Level Permissions

Import secret permissions as Keeper shared records:

**Prerequisite**: Thycotic users must already exist in Keeper before permissions can be applied. Provision them first (see [Import with User Migration](#import-with-user-migration)).

```bash
My Vault> import --format=thycotic https://<tenant>.secretservercloud.com
My Vault> download-membership --source=thycotic shared_folder_membership.json
My Vault> apply-membership shared_folder_membership.json
```

Download membership and apply permissions separately (parallel permission reads; see [Worker pool for permission loading](#worker-pool-for-permission-loading)):

```bash
My Vault> download-membership --source=thycotic --workers=4 shared_folder_membership.json
My Vault> apply-membership --full-sync shared_folder_membership.json
```

When `--workers` is omitted, **`download-membership` defaults to 4 workers** (valid range 1–16).

### Advanced Options

| Option | Description |
|--------|-------------|
| `--secret-ids` | Comma-separated list of specific secret IDs to import |
| `--folder` | Import into a separate Keeper folder |
| `--show-skipped` | Display records that could not be imported (always enabled for Thycotic imports) |
| `--add-users` | Provision Thycotic users as Keeper enterprise users |
| `--add-teams` | Create Keeper teams based on Thycotic groups and assign users |
| `--dry-run` | Preview changes without making them |
| `--old-domain` / `--new-domain` | Rewrite email domains in permission data |

The `import` command does **not** define `--verbose` or `--debug`. For detailed API traces, configure Python logging (for example `logging.DEBUG` on the `keepercommander` logger) before starting Commander.

## Features in Detail

### Restricted Secrets

Thycotic Secret Server restricts access to certain secrets. To import restricted secrets:

1. Your Thycotic user account must have the **"View Restricted Secret"** permission
2. During **secret import** (not during `--add-users` dry run), Commander reads each secret as follows:
   - Try a normal `GET` of the secret (and sensitive fields)
   - If that fails, **retry the same request with checkout query parameters** (`autoCheckout`, `autoCheckIn`, `autoComment`) so Delinea checks the secret out for the API read, then checks it back in

This checkout behavior applies only when loading secret content for import. It is not used for membership export or user provisioning previews.

No extra flags are required on the import command.

### User Migration

Use `--add-users` flag to:

1. Fetch Thycotic users from the tenant
2. Create matching Keeper enterprise users (pre-activated)
3. Then proceed with secret import

Users are matched by email address. Existing Keeper users are skipped.

Features:

- Automatic email extraction from multiple sources
- Name fallback to username if not available
- Inactive user handling
- Application account filtering

### Team Creation

Use `--add-teams` flag to:

1. Create Keeper teams from Thycotic groups
2. Assign users to teams based on group membership
3. Handle nested groups and complex hierarchies

Features:

- Automatic team naming from group names
- User assignment based on group membership
- Duplicate prevention (case-insensitive)
- Missing group handling

### Secret-Level Permissions

Create shared records with proper permissions mapping:

1. Import secrets normally
2. Run `download-membership --source=thycotic` to export permission mappings
3. Run `apply-membership` to create shared records with proper permissions

Supported permissions:

- View
- Manage Records
- Manage Users
- Transfer Records (owner only)

Features:

- Folder path normalization (both `/` and `\` separators)
- Record deduplication in multiple folders
- User detail caching for efficiency
- Graceful handling of missing roles (logs which roles cannot be mapped)
- Per-user result reporting (created, existing, invalid, failed)

### Performance Optimization

#### Worker Pool for Permission Loading

Reading permissions from Delinea (`download-membership`) can use a configurable worker pool for parallel fetches. The **`import` command does not use this worker pool**—only membership download (and related permission bulk loading in that flow).

```bash
My Vault> download-membership --source=thycotic --workers=4 memberships.json
```

- **Default**: 4 workers when `--workers` is omitted
- **Range**: 1–16 workers
- **`--workers=1`**: Sequential (no parallelization)
- **Queue limit**: At most `workers * 2` requests queued at a time
- **Results order**: Preserved in output

See also [Import with Secret-Level Permissions](#import-with-secret-level-permissions) for a typical `--workers` example.

#### Bulk Permission Endpoint

Efficient permission loading:

- One bulk GET to `/v1/secret-permissions` (no secretId filter)
- Groups results by secretId
- Falls back to per-secret requests if bulk call fails

#### Rate Limit Handling

Automatic retry on rate limits:

- Exponential backoff (5s base: 5s, 10s, 20s) is **always** applied on HTTP 429
- If a `Retry-After` header is present (capped at 300s), the wait uses the **longer** of `Retry-After` and the current backoff delay
- Maximum 3 retry attempts per request

## Error Handling

The import process continues even if individual items fail. Summary reports show:

**Skipped Secrets**: Secrets that could not be imported (with error details)

**Skipped Fields**: Individual fields that could not be imported (with specific reasons)

**Skipped Users**: Users that could not be created (with error details)

**Unmapped Roles**: Thycotic roles that don't map to Keeper (logged with affected secret count)

Use `--show-skipped` to display error tables after import completes.

## Troubleshooting

### Connection Errors

If you see connection timeouts:

- Verify Thycotic URL is accessible from your network
- Check firewall/proxy settings
- Verify authentication credentials
- Check network latency to Thycotic server

### Permission Denied

Ensure your Thycotic user has:

- "View Secret" permission on secrets to import
- "View Restricted Secret" permission for restricted secrets
- "View Group" permission if using `--add-users` or `--add-teams`
- API access enabled

### 2FA Failures

If TOTP authentication fails:

- Ensure your authenticator app is synchronized with server time
- Verify the TOTP code is entered within 30 seconds
- Re-run the import command if the code expires

### Rate Limiting

If you see "HTTP 429" errors:

- Import is automatically retrying with backoff
- Consider reducing `--workers` if downloading memberships
- Spread imports across multiple runs if needed

### Missing Groups

If groups don't appear in team creation:

- Verify the Thycotic user has "View Group" permission
- Check that groups contain members
- Review error logs for specific missing groups

## Performance Notes

- Import speed depends on:
  - Number of secrets being imported
  - Number of users and groups (if using `--add-users` or `--add-teams`)
  - Number of permission mappings (if downloading membership)
  - Network latency to Thycotic server
  - File attachment sizes
  - Whether restricted secrets require retry with checkout
  - Worker pool size (for membership download only; default 4)
- Large imports may take several minutes
- The import process logs progress every 10 secrets
- Permission loading uses bulk endpoints for efficiency

## Supported Delinea Secret Server Versions

Tested with Delinea Secret Server 10.x and later versions.

## Limitations

- **Secrets with Approval or Double Lock Policies**: Secrets requiring approval or protected by double lock policies cannot be imported. Request approval in Thycotic Secret Server or disable the double lock policy before importing.

- **Custom Secret Roles**: Custom Thycotic roles cannot be auto-mapped to Keeper permissions. Only standard roles are supported.

- **User and Team Creation with Reserved Domain**: Users and teams can only be created with email addresses from a reserved domain configured in Keeper. Emails with other domains will be skipped during `--add-users` or `--add-teams` operations.

## API Endpoints Used

The import uses the following Thycotic Secret Server API endpoints:

- `GET /api/v1/users` - List users
- `GET /api/v1/users/{id}` - Get user details
- `GET /api/v1/groups` - List groups
- `GET /api/v1/groups/{id}/users` - Get group members
- `GET /api/v1/secrets/lookup` - Search secrets (with folder/restriction filters)
- `GET /api/v1/secrets/{id}` - Get secret (with checkout parameters if needed)
- `GET /api/v1/secrets/{id}/fields/{slug}` - Get secret field (with checkout parameters if needed)
- `GET /api/v1/secret-permissions` - Get permissions (bulk or per-secret)
# Thycotic (Delinea) Secret Server Importer — NSF ACL Support

**Version:** 1.0  
**Status:** Production Ready  
**Last Updated:** 2026-11-05

---

## Quick Start (30 Seconds)

This module imports **Delinea Secret Server** into Keeper's Nested Share Folders with **automatic ACL mapping**.

```bash
# One-command import with full ACL
import --format=thycotic --nsf user@https://delinea.company.com/ --add-users --add-teams
```

You get:
- ✅ NSF folder structure
- ✅ All records in folders
- ✅ Folder-level permissions (NSF roles)
- ✅ Secret-level overrides (as direct record shares)
- ✅ Teams expanded to member permissions

---

## Overview

This module provides comprehensive import support for **Delinea Secret Server** (formerly Thycotic) into Keeper's Nested Share Folders (NSF) with **automatic ACL mapping**. Folder and secret-level permissions are intelligently translated from Delinea roles to NSF roles.

### Key Features

This is the **Thycotic NSF ACL feature** — a major enhancement that:

- 🎯 **Maps Delinea ACL to NSF roles** — automatically converts Delinea folder/secret permissions to NSF viewer/content-manager/full-manager/requestor roles
- 📁 **Folder-level permissions** — shared folder membership flows directly to NSF permissions
- 📋 **Secret-level overrides** — when a secret has different ACL than its folder, applies direct record shares
- 👥 **Team support** — Delinea groups expand to Keeper team grants
- 🔄 **Domain rewriting** — optional email domain migration (e.g., delinea.com → keeper.com)
- ✅ **Intelligent mapping** — detects lossy mappings and logs warnings

### Architecture

```
Delinea Secret Server
         ↓
    [REST API v1]
         ↓
ThycoticImporter.do_import()
         ├─→ _yield_nsf_shared_folders()
         │   ├─→ Fetch folders + permissions
         │   ├─→ thycotic_roles_to_nsf_role()  [role mapping]
         │   └─→ Yield NSF SharedFolder objects
         │
         └─→ Secret loop (per secret)
             ├─→ _permission_rows_for_secret()  [fetch secret ACL]
             ├─→ _attach_secret_nsf_permissions()  [compute deltas]
             └─→ Attach NsfRecordShare overrides
                     ↓
            [Keeper Vault]
                     ↓
        apply_nsf_folder_permissions()  [folder grants]
        apply_nsf_record_permissions()  [record shares]
```

---

## File Structure

### Main Implementation Files

```
keepercommander/importer/thycotic/
├── README.md                          ← You are here
├── thycotic.py                        ← ThycoticImporter + NSF methods
├── nsf_acl.py                         ← Role mapping functions (NEW)
├── pam/                               ← PAM-specific helpers
└── __init__.py
```

### Related Files

```
keepercommander/importer/
├── importer.py                        ← Base model types (NsfRecordShare, etc.)
├── nsf_import.py                      ← NSF permission applying (updated)
├── imp_exp.py                         ← Import pipeline (wired record perms)
└── commands.py                        ← CLI help text
```

### Tests

```
unit-tests/
├── test_thycotic_nsf_acl.py           ← 34 NSF ACL tests (NEW)
└── test_nsf_import.py                 ← 28 NSF import tests (no regression)
```

---

## How to Use

---

## Usage Examples

### Basic NSF Import with Full ACL

```bash
# Import Delinea folders, records, and all permissions (folder + secret-level)
import --format=thycotic --nsf user@https://delinea.company.com/ \
  --add-users --add-teams
```

**What happens:**
1. Connects to Delinea Secret Server
2. Fetches all folders with custom permissions
3. Creates NSF folder structure in Keeper
4. Grants NSF permissions based on Delinea folder ACL
5. For each secret: if ACL differs from folder, grants direct record share
6. Fetches and imports all secrets into NSF folders
7. Logs: `Granted N Nested Share Folder permission(s)` + `Granted M NSF record permission(s)`

### With Email Domain Rewriting

```bash
# Migrate from delinea.com → keeper.com email domain
import --format=thycotic --nsf user@https://delinea.company.com/ \
  --add-users --add-teams \
  --old-domain=delinea.com --new-domain=keeper.com
```

**Example:**  
- Delinea folder grant: `john.doe@delinea.com` (Owner folder + Owner secret)
- NSF folder grant: `john.doe@keeper.com` → full-manager role

### Dry Run (Preview)

```bash
# See what would be imported without writing to Keeper
import --format=thycotic --nsf user@https://delinea.company.com/ \
  --add-users --add-teams --dry-run
```

### Update Permissions Only (No Record Import)

```bash
# Re-sync permissions without importing/updating records
import --format=thycotic --nsf user@https://delinea.company.com/ \
  --add-users --add-teams --users
```

### Specific Secrets Only

```bash
# Import specific secret IDs (comma-separated)
import --format=thycotic --nsf user@https://delinea.company.com/ \
  --add-users --add-teams --secret-ids 123,456,789
```

### Step-by-Step Example

**Step 1: Authenticate to Keeper**
```bash
login
```

**Step 2: Import with Full ACL**
```bash
import --format=thycotic --nsf jane@https://delinea.company.com/ --add-users --add-teams
# Enter Delinea password when prompted
```

**Step 3: Check Logs**
```
✓ Loading X Records ...
✓ Granted N Nested Share Folder permission(s)
✓ Granted M NSF record permission(s)
```

**Step 4: Verify in Keeper**
- Open Nested Share Folders
- Check folder structure matches Delinea
- Check permissions (Manage → Members)

---

## Role Mapping Reference

### Folder + Secret ACL → NSF Role

| Delinea Folder | Delinea Secret | NSF Role | Notes |
|---|---|---|---|
| Owner | Owner | `full-manager` | Full control |
| Owner | Edit | `full-manager` | Full control |
| Edit | Owner | `content-manager` | Can manage content |
| Edit | Edit | `content-manager` | Can manage content |
| Add Secret | Owner | `content-manager` | Can add/manage secrets |
| Owner | View | `viewer` | **Lossy** ⚠️ — secret role wins |
| Edit | View | `viewer` | **Lossy** ⚠️ — secret role wins |
| View | View | `viewer` | Read-only |
| View | Edit | `content-manager` | Secret role wins |
| View | Owner | `full-manager` | Secret role wins |
| Any | List | `requestor` | Request-only (workflow) |
| (Group) | (any) | (secret role) | Team expanded to members |

**Legend:**
- 🔴 **Lossy** — folder role loses information; secret role takes precedence on that record

### Secret-Only ACL (Overrides Folder)

When a secret has different permission than its folder:

| Secret Role | NSF Role |
|---|---|
| List | `requestor` |
| View | `viewer` |
| Edit | `content-manager` |
| Owner | `full-manager` |

**Delta calculation example:**
```
Folder grants user1@example.com → viewer (folder Owner + secret View)
Secret grants user1@example.com → content-manager (secret Edit)
Result: Direct record share grants user1@example.com → content-manager (overrides folder viewer)
```

---

## Prerequisites & Setup

### Delinea Side

1. **User with API access**
   - Must have permission to read folders, secrets, and permissions
   - Enable REST API access (typically default in Secret Server)
   
2. **REST API v1 enabled** (default)
   - Endpoint: `https://<delinea-host>/api/v1/`
   - No special configuration needed

3. **Network access**
   - Keeper Commander must reach Delinea Server HTTPS endpoint
   - Port 443 (HTTPS)
   - No firewall rules needed beyond standard HTTPS

### Keeper Side

1. **Keeper Admin account** for Commander CLI
   - Run `login` in Commander to authenticate

2. **Destination NSF folder** (optional)
   - If not specified, creates at vault root
   - Use `--import-into <folder-path>` to target a parent folder

3. **Teams must exist** (for --add-teams)
   - Before running `--add-teams`, teams referenced in Delinea must be created in Keeper
   - Run `team-add <team-name>` to create teams first

4. **No file attachment downloads during tests**
   - Secret Server is queried for permissions only
   - File attachments still downloaded on import (uses --file-cache if needed)

### Required Packages

All dependencies are in `requirements.txt`:

```bash
pip install -r requirements.txt
```

Key packages:
- `requests` — HTTP calls to Delinea REST API
- `crypto` — Encryption for Keeper vault
- `protobuf` — Keeper protocol buffers

---

## Code Deep Dive

### Main Entry Point: `ThycoticImporter.do_import()`

Located in `thycotic.py` (line 247+)

**Flow:**
1. Authenticate to Delinea (prompt for username/password)
2. Load secret templates + TOTP codes (if csv present)
3. **NSF path only:**
   - Fetch folders **with permissions** (skip_permissions=False)
   - `_yield_nsf_shared_folders()` → NSF SharedFolder objects with roles
   - (Optional) Return early if `--users` flag set
4. Fetch secrets by ID
5. For each secret:
   - Build Record object
   - Determine record type from secret template
   - Extract fields (login, password, attachments, etc.)
   - **NSF path only:**
     - Call `_attach_secret_nsf_permissions()` to compute secret ACL deltas
6. Yield all records

### Role Mapping: `nsf_acl.py`

**Public functions:**

1. **`thycotic_roles_to_nsf_role(folder_role, secret_role)`**
   - Maps Delinea folder + secret roles to single NSF role
   - Handles View folder with secret role (secret wins)
   - Handles no folder role (uses secret role only)
   - Returns None if no permissions

2. **`thycotic_secret_role_to_nsf_role(secret_role)`**
   - Maps secret-only role to NSF role
   - Used for secret overrides

3. **`is_lossy_folder_secret_pair(folder_role, secret_role)`**
   - Detects lossy mappings (e.g., Owner folder + View secret)
   - Logs warnings on import

4. **`diff_secret_acl(folder_roles_by_email, secret_roles_by_email)`**
   - Returns list of `(email, nsf_role)` deltas
   - Only where secret role ≠ folder role
   - Used to populate `record.nsf_record_shares`

### Secret ACL Fetching: `_attach_secret_nsf_permissions()`

Located in `thycotic.py` (line 785+)

**Steps:**
1. Fetch secret permission rows via `_permission_rows_for_secret()`
2. For each permission:
   - Map to NSF role via `thycotic_secret_role_to_nsf_role()`
   - Expand groups to member emails (nested)
   - Apply email domain rewrite if `--old-domain`/`--new-domain`
3. Build `secret_nsf_role_by_email` map
4. Call `diff_secret_acl()` to compute deltas
5. Create `NsfRecordShare` objects, attach to `record.nsf_record_shares`

### Permission Application: `nsf_import.py`

**`apply_nsf_folder_permissions(params, folders, ...)`**
- Resolves folder by path (if uid not set)
- Calls `update_folder_v3(..., inherit_permissions=False)` if `break_inheritance=True`
- Grants each permission via `grant_folder_access_v3()` with role
- Handles throttle retries (exponential backoff)

**`apply_nsf_record_permissions(params, records, dry_run=False)`** (NEW)
- Iterates records with `nsf_record_shares`
- Builds batch payload: `{record_uid, email, access_role_type}`
- Calls `batch_create_record_shares_v3()` (1000 per batch)
- Logs successes + failures

### Pipeline Wiring: `imp_exp.py`

Located in `imp_exp.py` (line 1542+)

**After folders + records created:**
```python
if use_nsf and declared_nsf_folders and not dry_run:
    from .nsf_import import apply_nsf_folder_permissions, apply_nsf_record_permissions
    apply_nsf_folder_permissions(...)
    apply_nsf_record_permissions(params, records, dry_run=dry_run)
```

---

## Model Types

### `importer.py` — New Types

```python
class NsfRecordShare:
    """Per-user NSF record share override."""
    uid = None          # email or team ID
    role = None         # 'viewer', 'content-manager', 'full-manager', 'requestor'

# Extended classes:
Record.nsf_record_shares = None  # type: Optional[List[NsfRecordShare]]
SharedFolder.break_inheritance = None  # type: Optional[bool]
```

---

## Testing

### Run All Tests

```bash
cd Commander
python3 -m pytest unit-tests/test_thycotic_nsf_acl.py unit-tests/test_nsf_import.py -v
```

### Test Coverage

| Module | Tests | Purpose |
|--------|-------|---------|
| `test_thycotic_nsf_acl.py` | 34 | Role mapping, deltas, overrides |
| `test_nsf_import.py` | 28 | Existing NSF import (regression) |
| **Total** | **62** | All passing ✅ |

### Key Test Scenarios

**Role Mapping Tests:**
- Owner + Owner → full-manager
- View + View → viewer
- Owner + View → viewer (lossy)
- No folder role + secret role → secret role wins

**Delta Tests:**
- Folder grants viewer, secret grants content-manager → delta
- Multiple users with mixed deltas

**Integration (via test_nsf_import.py):**
- apply_nsf_folder_permissions with break_inheritance
- batch_create_record_shares_v3 with correct keys

---

## Logging & Monitoring

### Log Messages

**Success:**
```
Granted N Nested Share Folder permission(s)
Granted M NSF record permission(s)
```

**Warnings (non-blocking):**
```
Lossy NSF role mapping for folder <path>: <folder-role> folder + <secret-role> secret → <nsf-role>
Group <group-id> not found for folder <path> permissions
Failed to break inheritance on NSF folder "<path>": <error>
NSF folder permission for "<email>" on "<path>" failed: <error>
```

**Debug:**
```
Enter get_folders
Loaded N folders
Permission check progress: X of Y
```

### Dry Run Output

```bash
$ import --format=thycotic --nsf user@https://host/ --add-users --add-teams --dry-run
Would grant NSF folder "<path>" role "full-manager" to "<email>"
Would grant NSF record "<record_uid>" role "viewer" to "<email>"
```

---

## Quick Troubleshooting Checklist

| Issue | Check | Fix |
|-------|-------|-----|
| No permissions granted | Logs say "0 permissions" | Run `--dry-run` to see mapping |
| "Group not found" | Groups referenced but not in Keeper | Run `team-add <group-name>` first |
| "Lossy mapping" warning | Expected (lossy mappings logged) | Secret role takes precedence — check record |
| Import hangs | Large number of secrets/permissions | Run with smaller batch (--secret-ids) |
| Email wrong domain | Domain didn't rewrite | Confirm `--old-domain` matches actual |

---

## Advanced Troubleshooting

### Issue: "Folder permissions not granted"

**Causes:**
1. `SharedFolder.uid` incorrectly set to Delinea ID (should be None for path lookup)
2. `break_inheritance` not called before grants
3. NSF folder not created yet (check folder creation step)

**Solution:**
- Check logs for "Permission check progress"
- Run with `--dry-run` first to see what would be granted
- Verify folder exists in Keeper NSF (check folder UID)

### Issue: "Secret-level ACL not applied"

**Causes:**
1. `apply_nsf_record_permissions` not called (was in P0 gap)
2. `record.nsf_record_shares` is empty (no deltas found)
3. Record UID not set when reaching permission application

**Solution:**
- Confirm `imp_exp.py` wires the call (line 1545)
- Check if secret ACL actually differs from folder ACL
- Verify records imported successfully before permission stage

### Issue: "Invalid role name" warnings

**Causes:**
- Role name doesn't match NSF API contract
- Typo in custom role mapping

**Solution:**
- Run `from keepercommander.nested_share_folder.permissions import resolve_role_name`
- Valid roles: `requestor`, `viewer`, `share-manager`, `content-manager`, `content-share-manager`, `full-manager`
- Check thycotic_roles_to_nsf_role() logic

### Issue: "Group not found for folder permissions"

**Causes:**
1. Delinea group not in Keeper system
2. `--add-teams` flag not used
3. Team membership out of sync

**Solution:**
- Create Keeper teams before import: `team-add <team-name>`
- Use `--add-teams` flag to auto-create from Delinea
- Check Keeper vs Delinea team names match

---

## Performance Notes

### Batch Operations

- **Folder permissions:** 100 per API call (NSF_FOLDER_BATCH)
- **Record permissions:** 1000 per API call (NSF_RECORD_BATCH)
- **Throttle retries:** 5 attempts max, exponential backoff (10s base, 1.5x multiplier)

### Data Fetching

- **Groups:** Fetched once per import (cached)
- **Users:** Fetched once per import (cached)
- **Secrets:** Fetched in sequence (avoids memory overload)
- **Permissions:** Fetched per-secret on demand

### Typical Timeline

| Step | Duration | Notes |
|------|----------|-------|
| Auth + folder load | 1–5s | Depends on folder count |
| Folder ACL mapping | 1–2s | 34 tests: <1ms per mapping |
| Secret fetch | 10–30s | Depends on secret count |
| Secret ACL fetch | 5–15s | Depends on secret count |
| NSF folder creation | 5–10s | Batched 100 per call |
| Permission grants | 10–20s | Batched 1000 per call |
| **Total** | **30–90s** | For 100 folders, 1000 secrets |

---

## Related Documentation

### In This Repository

- **[THYCOTIC_NSF_ACL_AGENT_HANDOFF.md](../../images/THYCOTIC_NSF_ACL_AGENT_HANDOFF.md)** — Original design & gap analysis
- **[THYCOTIC_NSF_ACL_IMPLEMENTATION.md](../../THYCOTIC_NSF_ACL_IMPLEMENTATION.md)** — Complete implementation summary
- **[importer.py](../importer.py#L239)** — Base importer model types
- **[nsf_import.py](../nsf_import.py#L483)** — NSF permission applying functions

### External Resources

- **Delinea REST API Docs:** https://docs.delinea.com/secret-server/api-scripting/ (version-specific)
- **Keeper NSF Roles:** Check `keepercommander/nested_share_folder/permissions.py` for valid role names
- **Keeper Vault Sync:** `keepercommander/sync_down.py` — called before permission grants

---

## Contributing

### Adding a New Role Mapping

1. Edit `nsf_acl.py` → `thycotic_roles_to_nsf_role()`
2. Add mapping case
3. Add unit test in `test_thycotic_nsf_acl.py`
4. Run `pytest unit-tests/test_thycotic_nsf_acl.py -v` to verify
5. Update role mapping table in this README

### Debugging an Import

```python
# In thycotic.py, add logging:
import logging
logging.basicConfig(level=logging.DEBUG)

# Run import with debug output:
import --format=thycotic --nsf user@host/ --add-users
```

### Regression Testing

Always run before merging:
```bash
python3 -m pytest unit-tests/test_thycotic_nsf_acl.py unit-tests/test_nsf_import.py -q
```

---

---

## Complete Command Reference

```bash
# Full ACL import (recommended)
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams

# With domain rewrite (delinea.com → keeper.com)
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams \
  --old-domain=delinea.com --new-domain=keeper.com

# Permissions only (no record import)
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams --users

# Dry run (see what would happen)
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams --dry-run

# Specific secrets only
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams --secret-ids ID1,ID2,ID3

# Combine options
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams \
  --old-domain=delinea.com --new-domain=keeper.com --dry-run

# With import location
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams \
  --import-into "parent-folder-path"
```

---

## Architecture Overview (90 Seconds)

```
1. CONNECT to Delinea
   ↓
2. FETCH folders with permissions
   ↓
3. MAP Delinea roles → NSF roles
   ↓
4. YIELD NSF SharedFolder objects
   ↓
5. CREATE NSF folders + set break_inheritance
   ↓
6. GRANT folder permissions (nsf roles)
   ↓
7. FETCH secrets + FETCH secret ACL
   ↓
8. COMPUTE secret ACL deltas vs folder role
   ↓
9. ATTACH NsfRecordShare overrides to records
   ↓
10. GRANT record shares (deltas only)
   ↓
✓ Done
```

---

## Navigation by Role

| Role | Start With | Then Read |
|------|-----------|-----------|
| **New Developer** | "Quick Start" (this page) | "How to Use" → Code Deep Dive |
| **Code Reviewer** | "File Structure" | "Code Deep Dive" → Review changes |
| **QA / Tester** | "Testing" | Run test suite → Try `--dry-run` |
| **Operations** | "Command Reference" | Prerequisites & Setup |
| **Architect** | "Architecture" | Design Handoff (external doc) |

---

## Navigation by Topic

| Topic | Section |
|-------|---------|
| **Getting started** | Quick Start + Usage Examples |
| **Role mapping** | Role Mapping Reference |
| **Architecture** | Architecture Overview + Code Deep Dive |
| **Testing** | Testing |
| **Troubleshooting** | Quick Troubleshooting Checklist + Advanced Troubleshooting |
| **Commands** | Complete Command Reference |
| **Prerequisites** | Prerequisites & Setup |
| **Performance** | Performance Notes |

---

## Changelog

### v1.0 (2026-11-04) — Initial NSF ACL Release

✅ **P0 Fixes:**
- GAP-1: SharedFolder.uid → None (path-based lookup)
- GAP-5: break_inheritance applied
- GAP-8: Role mapping corrected (View+View, no-folder cases)
- GAP-4: Record permissions API payload fixed
- GAP-2: Record permissions wired into pipeline

✅ **P1 Features:**
- GAP-3: Secret-level ACL overrides
- GAP-6: Delinea groups support
- GAP-7: Email domain rewriting
- GAP-9: Nested group expansion

✅ **Testing:** 62 unit tests, all passing

---

## Support & Questions

For issues or clarifications:

1. **Check logs** — Enable debug logging to see detailed flow
2. **Review unit tests** — See `test_thycotic_nsf_acl.py` for examples
3. **Trace role mapping** — Print intermediate role values
4. **Verify prerequisites** — Confirm Delinea user, Keeper teams, NSF folder exist

---

**Last Updated:** November 4, 2026  
**Maintainer:** Keeper Security Engineering  
**Status:** Production Ready ✅
