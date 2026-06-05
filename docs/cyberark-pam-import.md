# CyberArk PAM Import Command — Technical Reference

## Overview

Imports privileged accounts from CyberArk (self-hosted PVWA or Privilege Cloud) into KeeperPAM as properly structured PAM records with folder hierarchy, credential rotation, session recording, and access control.

**Branch**: `feature/cyberark-pam-import` on `jlima8900/Commander`
**Commands**: `pam project cyberark-import` (alias: `ca`) and `pam project cyberark-cleanup` (alias: `CC`)
**Status**: 287 tests passing, 29 commits, rebased on Release v17.2.13

---

## What It Does

### Input: CyberArk PVWA REST API
Connects to CyberArk's `/PasswordVault/API/` endpoints to extract:
- **Accounts** — privileged credentials with platform type, address, username, password/SSH key
- **Safes** — container vaults that organize accounts (maps to Keeper folders)
- **Safe Members** — users/groups with granular permissions (maps to shared folder permissions)
- **Linked Accounts** — logon, reconcile, and enable accounts tied to resources
- **Master Policy** — session recording, rotation, tunneling settings
- **Vault Users/Groups** — matched to Keeper users/teams for permission migration

### Output: KeeperPAM Vault Records
Produces import JSON consumed by `edit.py` (PAMProjectImportCommand) / `extend.py` (PAMProjectExtendCommand):

```
Keeper Vault/
├── {Project} - Resources/          (shared folder)
│   ├── SafeA/                      (subfolder per CyberArk safe)
│   │   ├── pamMachine: linux1      (Unix SSH resource)
│   │   ├── pamDatabase: db1        (MSSQL/Oracle/MySQL/PostgreSQL)
│   │   └── pamMachine: firewall1   (network device)
│   └── SafeB/
│       └── pamMachine: win-dc1     (Windows + domain_name)
├── {Project} - Users/              (shared folder)
│   ├── SafeA/
│   │   ├── pamUser: root@linux1    (linked to pamMachine via launch_credentials)
│   │   ├── pamUser: sa@db1         (linked, with connect_database)
│   │   └── pamUser: admin@fw1      (linked)
│   └── SafeB/
│       ├── pamUser: admin@win-dc1  (linked, with distinguished_name)
│       ├── pamUser: svc (logon)    (CyberArk linked logon account)
│       ├── pamUser: recon (recon)  (CyberArk reconcile → administrative_credentials)
│       └── login: web-portal       (BusinessWebsite → login record with URL)
└── PAM Configuration record        (gateway, rotation schedule, session recording)
```

---

## Record Mapping

### Platform → Record Type

| CyberArk Platform | Keeper Record | Protocol | Port |
|---|---|---|---|
| UnixSSH | pamMachine | ssh | 22 |
| UnixSSHKey, UnixSSHKeys | pamMachine | ssh | 22 |
| WinDomain, WinLocalAccount, WinServerLocal, WinDesktopLocal | pamMachine | rdp | 3389 |
| MSSql | pamDatabase | mssql | 1433 |
| Oracle | pamDatabase | sql-server | 1521 |
| MySQL | pamDatabase | mysql | 3306 |
| PostgreSQL | pamDatabase | postgresql | 5432 |
| PaloAltoNetworks, CiscoIOS, CiscoASA, JuniperJunos, F5BigIP, CheckPointGAIA | pamMachine | ssh | 22 |
| CyberArk (internal) | pamMachine | ssh | 22 |
| BusinessWebsite | login | — | — |
| (empty platformId) | pamMachine | ssh | 22 |
| (unknown platformId) | pamMachine | ssh | 22 |

### Field Mapping

| CyberArk Field | Keeper Field | Where |
|---|---|---|
| address | host | resource |
| platformAccountProperties.Port | port | resource + pam_settings.connection |
| platformAccountProperties.LogonDomain | domain_name | resource (pamMachine only) |
| platformAccountProperties.Database | connect_database | pamUser (pamDatabase only) |
| platformAccountProperties.DistinguishedName | distinguished_name | pamUser |
| userName | login | pamUser (prefixed with LogonDomain\ if present) |
| password (retrieved) | password | pamUser |
| password (SSH key platforms or secretType=key) | private_pem_key | pamUser (password cleared) |
| secretManagement.automaticManagementEnabled | rotation_settings.enabled | pamUser (on/off) |
| secretManagement.manualManagementReason | notes | pamUser (annotated) |
| secretManagement.status=failure | notes | pamUser (FAILURE annotated) |
| safeName | folder_path | resource + users (under shared folder roots) |
| linkedAccounts.reconcileAccount | pam_settings.connection.administrative_credentials | resource |
| linkedAccounts.logonAccount | pamUser (nested) | resource.users[] |
| Master Policy | pam_configuration | connections, rotation, tunneling, session recording |

### Resource pam_settings Structure

Every resource (pamMachine/pamDatabase) gets:
```json
{
  "pam_settings": {
    "options": {
      "rotation": "on|off",
      "connections": "on",
      "tunneling": "off",
      "graphical_session_recording": "off"
    },
    "connection": {
      "protocol": "ssh|rdp|mssql|...",
      "port": "22|3389|...",
      "launch_credentials": "username@resource-title"
    }
  }
}
```

### User rotation_settings Structure

Every pamUser nested in a resource gets:
```json
{
  "rotation_settings": {
    "rotation": "general",
    "enabled": "on|off",
    "schedule": {"type": "on-demand"}
  }
}
```

`edit.py` resolves `rotation_settings.resource` → parent machine UID automatically at import time.

---

## Authentication

### Self-Hosted PVWA
- Login types: CyberArk, LDAP, RADIUS, Windows
- Auth token via `POST /PasswordVault/API/Auth/{type}/Logon`
- SSL verification optional (`--no-verify-ssl`)

### Privilege Cloud (*.cyberark.cloud)
- OAuth2 service account via `POST /oauth2/platformtoken`
- Tenant ID discovery via `platform-discovery.cyberark.cloud`
- Tenant formats: `abc1234`, `mycompany`, `abc1234.id`, `tenant.my.idaptive.app`, full URL
- URL rewrite: `tenant.cyberark.cloud` → `tenant.privilegecloud.cyberark.cloud`
- SSL always enforced

### Environment Variables
| Variable | Purpose |
|---|---|
| KEEPER_CYBERARK_ID_TENANT | Identity tenant ID (Privilege Cloud) |
| KEEPER_CYBERARK_USERNAME | Username or service account client ID |
| KEEPER_CYBERARK_PASSWORD | Password or client secret |
| KEEPER_CYBERARK_LOGON_TYPE | Logon type for self-hosted (CyberArk/LDAP/RADIUS/Windows) |
| KEEPER_CYBERARK_SAFES | Comma-separated safe names |
| KEEPER_CYBERARK_SAFES_PATH | Path to safes.txt file |
| KEEPER_CYBERARK_TICKETING_SYSTEM | Ticketing system name (for strict policies) |
| KEEPER_CYBERARK_TICKET_ID | Ticket ID (for strict policies) |

---

## CLI Usage

### Import Command
```bash
# Basic import from self-hosted PVWA
pam project cyberark-import pvwa.company.com --name "CyberArk Migration" --gateway "My Gateway"

# Privilege Cloud
pam project cyberark-import mycompany.cyberark.cloud --name "Cloud Import"

# Dry run with JSON output
pam project cyberark-import pvwa.company.com --dry-run --output import.json --include-credentials

# Filter specific safes
pam project cyberark-import pvwa.company.com --safes "Production,Staging" --exclude-safes "Archive*"

# Extend existing project
pam project cyberark-import pvwa.company.com --config <pam-config-uid>

# Skip linked accounts and safe members
pam project cyberark-import pvwa.company.com --skip-linked-accounts --skip-members

# Custom platform mapping
pam project cyberark-import pvwa.company.com --platform-map platforms.json
```

### Cleanup Command
```bash
# Remove imported project
pam project cyberark-cleanup --name "CyberArk Migration"

# By config UID
pam project cyberark-cleanup --config <pam-config-uid>

# Dry run
pam project cyberark-cleanup --name "CyberArk Migration" --dry-run
```

### All Flags
| Flag | Description |
|---|---|
| `server` | PVWA host (required) |
| `--name`, `-n` | Project name |
| `--config`, `-c` | Extend existing PAM config UID |
| `--gateway`, `-g` | Gateway name or UID |
| `--folder-mode` | flat, exact, ksm (default) |
| `--safes` | Include only these safes (comma/glob) |
| `--exclude-safes` | Exclude safes (comma/glob) |
| `--list-safes` | List safes and exit |
| `--dry-run`, `-d` | Preview without vault changes |
| `--output`, `-o` | Save import JSON to file |
| `--include-credentials` | Include passwords in output/dry-run |
| `--estimate` | Estimate import size and exit |
| `--yes`, `-y` | Skip confirmation prompt |
| `--skip-users` | Don't import user records |
| `--skip-linked-accounts` | Don't fetch linked accounts |
| `--skip-members` | Don't fetch safe members |
| `--batch-size` | Records per batch (default: 100) |
| `--batch-delay` | Seconds between batches (default: 0.5) |
| `--platform-map` | Custom platform mapping JSON file |
| `--state-filter` | Filter by CPM status (e.g. "success,failure") |
| `--user-map` | CyberArk→Keeper user mapping JSON file |
| `--no-verify-ssl` | Disable SSL verification (self-hosted only) |
| `--include-system-safes` | Include system safes (PSM, PasswordManager, etc.) |

---

## Safe Member Permission Mapping

CyberArk's 24 granular permissions map to Keeper's 4-tier model:

| Tier | CyberArk Permissions Required | Keeper Result |
|---|---|---|
| View | useAccounts + listAccounts | can_edit=false, manage_records=false |
| Edit | + addAccounts + (updateAccountContent or updateAccountProperties) | can_edit=true, manage_records=true |
| Manage | + manageSafe + manageSafeMembers | can_edit=true, can_share=true, manage_users=true |

Unmapped permissions logged in report: accessWithoutConfirmation, requestsAuthorizationLevel1/2

---

## System Safes (Excluded by Default)

System, VaultInternal, Notification Engine, SharedAuth_Internal, PVWAUserPrefs, PVWAConfig, PVWAReports, PVWATaskDefinitions, PVWAPrivateUserPrefs, PVWAPublicData, PVWATicketingSystem, AccountsFeed, PSM, xRay, PIMSuRecordings, xRay_Config, AccountsFeedAcc, PasswordManager_Pending, PasswordManagerShared, PasswordManager_workspace, PasswordManager_ADInternal, PasswordManager, SCIM Config, PSMSessions, PSMUnmanagedSessionAccounts, PSMLiveSessions, PSMNotifications, PSMRecordings

Override with `--include-system-safes`.

---

## Pre-Import Validation

Before building the import JSON, the importer warns about:
- Resources missing host/address
- Users without password or SSH key
- Standalone login records not linked to resources
- Rotation enabled but no credentials (rotation will fail)

---

## CyberArk Products Supported

| Product | Auth Method | Status |
|---|---|---|
| Self-hosted PVWA (v10.4+) | CyberArk/LDAP/RADIUS/Windows | Implemented |
| Privilege Cloud (SaaS) | OAuth2 service account | Implemented |
| Privilege Cloud Shared Services (ISPSS) | OAuth2 with platform discovery | Implemented |
| PrivateArk / Digital Vault | No REST API | Not accessible |
| User Portal (Identity) | Separate importer (cyberark_portal) | Different scope |

---

## Security

- SSRF protection: validates PVWA host, rejects private/reserved IPs
- Secure temp files: atomic creation (0o600), zero-overwrite before unlink
- Input validation: account IDs, safe names, logon types regex-checked
- No credential logging: passwords never appear in logs or error messages
- Rate limit handling: automatic retry on HTTP 429 with exponential backoff
- Pagination cap: MAX_FETCH_RECORDS (50,000) prevents OOM attacks
- Ticket ID support: for CyberArk policies requiring audit trail

---

## Project Stats

| Metric | Value |
|---|---|
| Source files | cyberark_pam.py (1,648 lines), cyberark_import.py (1,065 lines) |
| Test file | test_cyberark_pam_import.py (3,164 lines) |
| Total code | 5,877 lines |
| Tests | 287 (unit + integration) |
| Commits | 29 on feature branch |
| Base | Keeper Commander Release v17.2.13 |
