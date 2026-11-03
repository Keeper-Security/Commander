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

## Requirements

The following Python packages are required:

```bash
pip3 install requests
```

For user migration and team features:

```bash
pip3 install tabulate
```

## Installation

These are already included in the base `requirements.txt` for Commander.

## Usage

### Basic Import

Import all secrets from Thycotic Secret Server:

```bash
keeper> import --format=thycotic https://<tenant>.secretservercloud.com
```

This will prompt for:
- **Username**: Your Thycotic username
- **Password**: Your Thycotic password
- **2FA Code**: TOTP code if two-factor authentication is enabled

### Import Specific Folders

Import secrets from a single folder (matched by folder name, case-insensitive):

```bash
keeper> import --format=thycotic --filter-folder=finance https://<tenant>.secretservercloud.com
```

### Interactive Folder Selection

Browse and select folders interactively:

```bash
keeper> import --format=thycotic https://<tenant>.secretservercloud.com
# Then choose folders from the interactive menu
```

### Import with User Migration

Provision Thycotic users as Keeper enterprise users before importing secrets:

```bash
keeper> import --format=thycotic --add-users https://<tenant>.secretservercloud.com
```

**Dry Run Mode**: Preview users to be created without actually creating them:

```bash
keeper> import --format=thycotic --add-users --dry-run https://<tenant>.secretservercloud.com
```

### Import with Team Creation

Create Keeper teams based on Thycotic groups and assign users:

```bash
keeper> import --format=thycotic --add-users --add-teams https://<tenant>.secretservercloud.com
```

**Dry Run Mode**: Preview teams and user assignments without creating them:

```bash
keeper> import --format=thycotic --add-users --add-teams --dry-run https://<tenant>.secretservercloud.com
```

### Import with Secret-Level Permissions

Import secret permissions as Keeper shared records:

**Prerequisite**: The Thycotic users must already exist in Keeper before permissions can be applied. If they don't, provision them first (see [Import with User Migration](#import-with-user-migration)).

```bash
keeper> import --format=thycotic https://<tenant>.secretservercloud.com
keeper> download-membership --source=thycotic shared_folder_membership.json
keeper> apply-membership shared_folder_membership.json
```

Or download membership and apply permissions separately with worker pool:

```bash
keeper> download-membership --source=thycotic --workers=4 shared_folder_membership.json
keeper> apply-membership --full-sync shared_folder_membership.json
```

### Advanced Options

| Option | Description |
|--------|-------------|
| `--secret-ids` | Comma-separated list of specific secret IDs to import |
| `--folder` | Import into a separate Keeper folder |
| `--show-skipped` | Display records that could not be imported |
| `--add-users` | Provision Thycotic users as Keeper enterprise users |
| `--add-teams` | Create Keeper teams based on Thycotic groups and assign users |
| `--dry-run` | Preview changes without making them |

## Features in Detail

### Restricted Secrets

Thycotic Secret Server restricts access to certain secrets. To import restricted secrets:

1. Your Thycotic user account must have the **"View Restricted Secret"** permission
2. The import automatically attempts to:
   - First read the secret normally
   - If that fails, retry with checkout parameters (`autoCheckout`, `autoCheckIn`, `autoComment`)

This is handled transparently - no additional configuration is required.


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

Reading permissions from Delinea (`download-membership`) can use a configurable worker pool for parallel fetches. The import itself does not use the worker pool.

```bash
keeper> download-membership --source=thycotic --workers=4 memberships.json
```

- **Default**: 4 workers
- **Range**: 1-16 workers
- **Worker=1**: Single-threaded (no parallelization)
- **Queue Limit**: At most `workers * 2` requests queued at a time
- **Results Order**: Preserved in output

#### Bulk Permission Endpoint

Efficient permission loading:
- One bulk GET to `/v1/secret-permissions` (no secretId filter)
- Groups results by secretId
- Falls back to per-secret requests if bulk call fails

#### Rate Limit Handling

Automatic retry on rate limits:
- Exponential backoff (5s base: 5s, 10s, 20s) is always applied
- If a `Retry-After` header is present (capped at 300s), the longer of `Retry-After` and the backoff is used
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
  - Worker pool size (for membership download)
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

