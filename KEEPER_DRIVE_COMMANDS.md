# KeeperDrive Commands Reference

## Overview

KeeperDrive commands manage folders, records, sharing, and permissions using the Keeper v3 API.
All commands are prefixed with `kd-` and require authentication and a synced vault.

**Permission roles** (used across folder and record sharing commands):

| Role | Description |
|---|---|
| `contributor` | Can request access, list records/folders |
| `viewer` | Read-only access |
| `shared-manager` | Can manage access grants |
| `content-manager` | Can add/edit records |
| `content-share-manager` | Can add/remove/edit records and manage access |
| `manager` | Full control |

---

## Table of Contents

1. [Folder Management](#folder-management)
   - [kd-mkdir](#kd-mkdir)
   - [kd-rndir](#kd-rndir)
   - [kd-list](#kd-list)
   - [kd-rmdir](#kd-rmdir)
2. [Folder Access](#folder-access)
   - [kd-share-folder](#kd-share-folder)
   - [kd-folder-access](#kd-folder-access)
3. [Record Management](#record-management)
   - [kd-record-add](#kd-record-add)
   - [kd-record-update](#kd-record-update)
   - [kd-rm](#kd-rm)
4. [Folder-Record Linking](#folder-record-linking)
   - [kd-add-record-to-folder](#kd-add-record-to-folder)
   - [kd-remove-record-from-folder](#kd-remove-record-from-folder)
   - [kd-ln](#kd-ln)
   - [kd-shortcut](#kd-shortcut)
5. [Record Sharing](#record-sharing)
   - [kd-share-record](#kd-share-record)
   - [kd-record-permission](#kd-record-permission)
   - [kd-transfer-record](#kd-transfer-record)
6. [Inspection and Display](#inspection-and-display)
   - [kd-get](#kd-get)
   - [kd-record-details](#kd-record-details)
   - [kd-record-access](#kd-record-access)

---

## Folder Management

### kd-mkdir

Create a new KeeperDrive folder. Use `/` as a path separator to create a nested hierarchy; use `//` to embed a literal slash in a folder name.

**Syntax:**
```
kd-mkdir <folder_name_or_path> [options]
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `folder` | Yes | Folder name or path (e.g. `Projects/Work`) |

**Options:**
| Flag | Description |
|---|---|
| `-p`, `--parents` | Create intermediate parent folders as needed |
| `--color COLOR` | Folder color: `none` `red` `orange` `yellow` `green` `blue` `gray` |
| `--no-inherit` | Do not inherit parent folder permissions |

**Examples:**
```bash
# Create a single folder at root
kd-mkdir "My Projects"

# Create a nested path (creates Work inside Projects)
kd-mkdir "Projects/Work" --parents

# Create a folder with a colour
kd-mkdir "Sensitive" --color red --no-inherit
```

---

### kd-rndir

Rename a folder, change its colour, or update its permission-inheritance setting.

**Syntax:**
```
kd-rndir <folder> [options]
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `folder` | Yes | Folder UID, name, or path |

**Options:**
| Flag | Description |
|---|---|
| `-n NAME`, `--name NAME` | New folder name |
| `--color COLOR` | New colour: `none` `red` `orange` `yellow` `green` `blue` `purple` `pink` `gray` |
| `--inherit` | Enable permission inheritance from parent |
| `--no-inherit` | Disable permission inheritance |
| `-q`, `--quiet` | Suppress confirmation message |

At least one option is required.

**Examples:**
```bash
kd-rndir "Old Name" --name "New Name"
kd-rndir abc123 --color blue
kd-rndir abc123 --name "Archive Q4" --color gray --inherit
```

---

### kd-list

List KeeperDrive folders and records from the local cache.

**Syntax:**
```
kd-list [options]
```

**Options:**
| Flag | Description |
|---|---|
| `--folders` | Show only folders |
| `--records` | Show only records |
| `-v`, `--verbose` | Show detailed information (parent UID, folder location) |
| `-p`, `--permissions` | Show permission/access information |
| `--format FORMAT` | Output format: `table` (default) `csv` `json` |
| `--output FILE` | Write output to file (csv/json only) |

If neither `--folders` nor `--records` is given, both are shown.

**Examples:**
```bash
kd-list
kd-list --folders --verbose
kd-list --records --format json --output records.json
kd-list -v -p
```

---

### kd-rmdir

Remove one or more KeeperDrive folders. Always previews impact first.

**Syntax:**
```
kd-rmdir <folder> [<folder>...] [options]
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `folders` | Yes | Folder UID(s) or name(s) to remove (max 100) |

**Options:**
| Flag | Description |
|---|---|
| `-o`, `--operation OP` | `folder-trash` (default, recoverable) or `delete-permanent` (irreversible) |
| `-f`, `--force` | Skip confirmation, execute after preview |
| `--dry-run` | Preview only, do not delete |
| `-q`, `--quiet` | Suppress per-folder detail in preview |

**Examples:**
```bash
# Move folder to trash (recoverable)
kd-rmdir "Old Projects"

# Preview deletion without committing
kd-rmdir abc123 --dry-run

# Permanently delete with no prompt
kd-rmdir abc123 def456 --operation delete-permanent --force
```

---

## Folder Access

### kd-share-folder

Grant, update, or remove a user's access to one or more KeeperDrive folders. The action is controlled by `--action` (default: `grant`).

**Syntax:**
```
kd-share-folder <folder> [<folder>...] -e <email> [options]
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `folder` | Yes | Folder UID(s), name(s), or path(s) |

**Options:**
| Flag | Description |
|---|---|
| `-e EMAIL`, `--email EMAIL` | Recipient email. Repeatable: `-e user1@example.com -e user2@example.com` |
| `-a ACTION`, `--action ACTION` | `grant` (default), `update`, `remove` |
| `-r ROLE`, `--role ROLE` | Permission role (default: `viewer`). Required for `grant`/`update` |
| `--expire-at TIMESTAMP` | Expiration as ISO datetime `yyyy-MM-ddTHH:MM:SSZ` or `never` |
| `--expire-in PERIOD` | Expiration as period: `30d` `6mo` `1y` `24h` `30mi` or `never` |

**Examples:**
```bash
# Grant viewer access
kd-share-folder "My Projects" -e colleague@example.com

# Grant manager access
kd-share-folder abc123 -e manager@example.com -r manager

# Grant access expiring in 7 days
kd-share-folder abc123 -e temp@example.com -r viewer --expire-in 7d

# Update role to content-manager
kd-share-folder abc123 -e user@example.com -a update -r content-manager

# Remove access
kd-share-folder abc123 -e user@example.com -a remove

# Grant access to multiple users and folders
kd-share-folder abc123 def456 -e user1@example.com -e user2@example.com -r viewer
```

---

### kd-folder-access

Show all accessors (users and teams) for one or more folders.

**Syntax:**
```
kd-folder-access <folder> [<folder>...] [options]
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `folder_uids` | Yes | Folder UID(s), name(s), or path(s) (max 100) |

**Options:**
| Flag | Description |
|---|---|
| `-v`, `--verbose` | Show full per-permission breakdown |

**Examples:**
```bash
kd-folder-access abc123
kd-folder-access abc123 def456 --verbose
```

---

## Record Management

### kd-record-add

Create a new KeeperDrive record. Fields are specified using `type=value` or `type.label=value` notation.

**Syntax:**
```
kd-record-add -t <title> -rt <type> [options] [field=value ...]
```

**Options:**
| Flag | Description |
|---|---|
| `-t TITLE`, `--title TITLE` | Record title (required) |
| `-rt TYPE`, `--record-type TYPE` | Record type, e.g. `login`, `general` (required) |
| `-n NOTES`, `--notes NOTES` | Record notes |
| `--folder FOLDER` | Folder UID or name (omit for vault root) |
| `-f`, `--force` | Ignore field-validation warnings |
| `--syntax-help` | Display full field notation syntax |

**Examples:**
```bash
# Create a login record at root
kd-record-add -t "Gmail" -rt login login=user@gmail.com password=Secret123

# Create in a specific folder
kd-record-add -t "Dev Server" -rt login --folder "Infrastructure" \
  login=root password=Pass123 url=ssh://dev.example.com

# Show field syntax help
kd-record-add --syntax-help
```

---

### kd-record-update

Update an existing KeeperDrive record's title, type, notes, or field values.

**Syntax:**
```
kd-record-update -r <record_uid> [-r <record_uid>...] [options] [field=value ...]
```

**Options:**
| Flag | Description |
|---|---|
| `-r UID`, `--record UID` | Record UID (required). Repeatable: `-r uid1 -r uid2` |
| `-t TITLE`, `--title TITLE` | New title |
| `-rt TYPE`, `--record-type TYPE` | New record type |
| `-n NOTES`, `--notes NOTES` | New/append notes |
| `-f`, `--force` | Ignore field-validation warnings |
| `--syntax-help` | Display full field notation syntax |

**Examples:**
```bash
kd-record-update -r rec123 -t "Updated Title"
kd-record-update -r rec123 password=NewPass123
kd-record-update -r rec123 -t "Production DB" -n "Rotated 2025-03-01" password=NewPass

# Update two records with the same new title
kd-record-update -r rec123 "Shared Title"
```

---

### kd-rm

Remove (trash or unlink) one or more KeeperDrive records. Always shows a preview before executing.

**Syntax:**
```
kd-rm <record> [<record>...] [options]
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `records` | Yes | Record UID(s) or title(s) to remove (max 500) |

**Options:**
| Flag | Description |
|---|---|
| `-f FOLDER`, `--folder FOLDER` | Folder context (required for `unlink`) |
| `-o OP`, `--operation OP` | `owner-trash` (default), `folder-trash`, `unlink` |
| `--force` | Skip confirmation after preview |
| `--dry-run` | Preview only, do not delete |

**Operation types:**
| Operation | Effect |
|---|---|
| `owner-trash` | Move record to owner's trash (recoverable) |
| `folder-trash` | Remove record from a folder and trash it |
| `unlink` | Remove record from a specific folder only (requires `--folder`) |

**Examples:**
```bash
# Trash a record (preview then confirm)
kd-rm rec123abc

# Unlink a record from a specific folder
kd-rm rec123abc --folder "Projects" --operation unlink

# Dry-run to inspect impact
kd-rm rec123abc rec456def --dry-run

# Force-delete multiple records
kd-rm rec123abc rec456def --force
```

---

## Folder-Record Linking

### kd-add-record-to-folder

Add an existing record to a folder (named flags).

**Syntax:**
```
kd-add-record-to-folder --folder <folder> --record <record_uid>
```

**Options:**
| Flag | Required | Description |
|---|---|---|
| `--folder FOLDER` | Yes | Folder UID, name, or path |
| `--record UID` | Yes | Record UID to add |

**Example:**
```bash
kd-add-record-to-folder --folder "My Projects" --record rec123abc
```

---

### kd-remove-record-from-folder

Remove a record from a folder (does not delete the record).

**Syntax:**
```
kd-remove-record-from-folder --folder <folder> --record <record_uid>
```

**Options:**
| Flag | Required | Description |
|---|---|---|
| `--folder FOLDER` | Yes | Folder UID, name, or path |
| `--record UID` | Yes | Record UID to remove |

**Example:**
```bash
kd-remove-record-from-folder --folder abc123 --record rec456def
```

---

### kd-ln

Link a record into a folder using short positional syntax (equivalent to `kd-add-record-to-folder`).

**Syntax:**
```
kd-ln <record_uid> <folder_uid>
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `src` | Yes | Record UID or title |
| `dst` | Yes | Destination folder UID or name |

**Example:**
```bash
kd-ln rec123abc abc123folder
```

---

### kd-shortcut

Manage records that appear in more than one folder (shortcuts / multi-folder links).

**Subcommands:**

#### kd-shortcut list

List all records linked to more than one folder.

```
kd-shortcut list [target] [--format FORMAT] [--output FILE]
```

| Argument / Flag | Description |
|---|---|
| `target` | Optional record UID/title or folder path to filter results |
| `--format FORMAT` | `table` (default), `csv`, `json` |
| `--output FILE` | Write csv/json output to file |

```bash
kd-shortcut list
kd-shortcut list "My Record"
kd-shortcut list "Projects" --format json
```

#### kd-shortcut keep

Keep a record in exactly one folder, removing it from all others.

```
kd-shortcut keep <target> [folder] [--force]
```

| Argument / Flag | Description |
|---|---|
| `target` | Record UID or title |
| `folder` | Folder UID or path to keep the record in (defaults to current folder) |
| `-f`, `--force` | Skip confirmation prompt |

```bash
kd-shortcut keep rec123abc "My Projects"
kd-shortcut keep rec123abc --force
```

---

## Record Sharing

### kd-share-record

Grant, update, or revoke a user's access to a record. All three actions are handled by one command via `--action`.

**Syntax:**
```
kd-share-record <record> -e <email> [options]
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `record` | Yes | Record UID or folder UID (with `-R` for bulk) |

**Options:**
| Flag | Description |
|---|---|
| `-e EMAIL`, `--email EMAIL` | Recipient email (required). Repeatable: `-e user1@example.com -e user2@example.com` |
| `-a ACTION`, `--action ACTION` | `grant` (default), `update`, `revoke`, `owner` (transfer ownership) |
| `-r ROLE`, `--role ROLE` | Permission role. Required for `grant`/`update` |
| `-R`, `--recursive` | Apply to all records in a folder and sub-folders |
| `--contacts-only` | Only share with known contacts |
| `-f`, `--force` | Skip confirmation prompts |
| `--dry-run` | Preview changes without committing |
| `--expire-at TIMESTAMP` | Expiration as ISO datetime or `never` |
| `--expire-in PERIOD` | Expiration as period: `30d` `6mo` `1y` `24h` `30mi` or `never` |

**Examples:**
```bash
# Grant viewer access
kd-share-record rec123abc -e colleague@example.com -r viewer

# Grant to multiple recipients
kd-share-record rec123abc -e user1@example.com -e user2@example.com -r viewer

# Update role to content-manager
kd-share-record rec123abc -e colleague@example.com -a update -r content-manager

# Revoke access
kd-share-record rec123abc -e colleague@example.com -a revoke

# Grant access with expiry in 30 days
kd-share-record rec123abc -e temp@example.com -r viewer --expire-in 30d

# Bulk share all records in a folder
kd-share-record folderabc -e team@example.com -r viewer -R

# Transfer ownership to another user (single recipient only)
kd-share-record rec123abc -e newowner@example.com -a owner

# Dry-run preview
kd-share-record rec123abc -e user@example.com -r manager --dry-run
```

> **Note:** `-a owner` transfers record ownership. Only one recipient is allowed. You will lose access to the record after the transfer.

---

### kd-record-permission

Bulk-update sharing permissions across all records in a folder (and optionally its sub-folders).

**Syntax:**
```
kd-record-permission -a <action> [folder] [options]
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `folder` | No | Folder UID or path (omit for root) |

**Options:**
| Flag | Description |
|---|---|
| `-a ACTION`, `--action ACTION` | `grant` or `revoke` (required) |
| `-r ROLE`, `--role ROLE` | Role to grant, or role to filter for revoke |
| `-R`, `--recursive` | Apply to all sub-folders |
| `-f`, `--force` | Apply without confirmation |
| `--dry-run` | Preview changes without committing |

**Examples:**
```bash
# Preview: grant viewer to everyone in a folder
kd-record-permission -a grant -r viewer "My Projects" --dry-run

# Apply: revoke a specific role from all records in folder tree
kd-record-permission -a revoke -r viewer "Archive" -R --force

# Grant viewer to all root-level KD records
kd-record-permission -a grant -r viewer
```

---

### kd-transfer-record

Transfer record ownership to another user. **You permanently lose access after this operation.**

**Syntax:**
```
kd-transfer-record <record_uid> [<record_uid>...] <new_owner_email>
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `record_uids` | Yes | UID(s) of the records to transfer |
| `new_owner_email` | Yes | Email of the new owner |

**Examples:**
```bash
kd-transfer-record rec123abc newowner@example.com

# Transfer multiple records to the same new owner
kd-transfer-record rec123abc rec456def newowner@example.com
```

> **Warning:** After transfer you will no longer have access to this record. This cannot be easily reversed.

---

## Inspection and Display

### kd-get

Show full details for a record or folder by UID or title — fields, notes, and access list.

**Syntax:**
```
kd-get <uid> [options]
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `uid` | Yes | Record UID, folder UID, or title/name |

**Options:**
| Flag | Description |
|---|---|
| `--format FORMAT` | `detail` (default) or `json` |
| `-v`, `--verbose` | Show full per-permission breakdown for each accessor |
| `--unmask` | Reveal masked field values (passwords, secrets) |

**Examples:**
```bash
kd-get rec123abc
kd-get "Gmail Account" --unmask
kd-get abc123folder --verbose
kd-get rec123abc --format json
```

---

### kd-record-details

Get metadata (title, type, version, revision) for one or more records.

**Syntax:**
```
kd-record-details <record_uid> [<record_uid>...] [options]
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `record_uids` | Yes | One or more record UIDs |

**Options:**
| Flag | Description |
|---|---|
| `--format FORMAT` | `table` (default) or `json` |

**Examples:**
```bash
kd-record-details rec123abc
kd-record-details rec123abc rec456def rec789ghi
kd-record-details rec123abc --format json
```

---

### kd-record-access

Show who has access to one or more records and at what role.

**Syntax:**
```
kd-record-access <record_uid> [<record_uid>...] [options]
```

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `record_uids` | Yes | One or more record UIDs |

**Options:**
| Flag | Description |
|---|---|
| `--format FORMAT` | `table` (default) or `json` |
| `-v`, `--verbose` | Show individual permission flags in addition to the role name |

**Examples:**
```bash
kd-record-access rec123abc
kd-record-access rec123abc rec456def --verbose
kd-record-access rec123abc --format json
```

---

## Quick Reference

### Folder commands
| Command | Description |
|---|---|
| `kd-mkdir` | Create folder(s) |
| `kd-rndir` | Rename / recolour a folder |
| `kd-list` | List folders and records |
| `kd-rmdir` | Remove folder(s) |
| `kd-share-folder` | Grant / update / remove folder access |
| `kd-folder-access` | List all accessors of a folder |

### Record commands
| Command | Description |
|---|---|
| `kd-record-add` | Create a record |
| `kd-record-update` | Update a record |
| `kd-rm` | Remove / trash / unlink a record |
| `kd-get` | Show full record or folder details |
| `kd-record-details` | Get record metadata (batch) |
| `kd-record-access` | List record accessors (batch) |

### Linking commands
| Command | Description |
|---|---|
| `kd-add-record-to-folder` | Add record to folder (named flags) |
| `kd-remove-record-from-folder` | Remove record from folder (named flags) |
| `kd-ln` | Link record to folder (positional syntax) |
| `kd-shortcut list` | List multi-folder records |
| `kd-shortcut keep` | Keep record in one folder, unlink from rest |

### Sharing commands
| Command | Description |
|---|---|
| `kd-share-record` | Grant / revoke / transfer ownership of a record |
| `kd-record-permission` | Bulk update sharing across a folder |
| `kd-transfer-record` | Transfer record ownership (dedicated command) |

---

## Common Workflows

### Set up a shared project folder

```bash
# 1. Create folder
kd-mkdir "Client Projects" --color blue

# 2. Add a record
kd-record-add -t "Client Portal" -rt login --folder "Client Projects" \
  login=admin@client.com password=Secret123 url=https://portal.client.com

# 3. Share folder with team
kd-share-folder "Client Projects" -e colleague@company.com -r content-manager

# 4. Verify
kd-list --folders --verbose
kd-folder-access "Client Projects"
```

### Share a record with time-limited access

```bash
# Grant 30-day access
kd-share-record rec123abc -e contractor@external.com -r viewer --expire-in 30d

# Check who has access
kd-record-access rec123abc

# Revoke when done
kd-share-record rec123abc -e contractor@external.com -a revoke
```

### Clean up multi-folder shortcuts

```bash
# Find records in multiple folders
kd-shortcut list

# Keep a record in only one folder
kd-shortcut keep "My Record" "Preferred Folder"
```

### Safely remove a folder

```bash
# Preview impact
kd-rmdir "Old Archive" --dry-run

# Trash (recoverable)
kd-rmdir "Old Archive"

# Or permanently delete
kd-rmdir "Old Archive" --operation delete-permanent --force
```

---

## Expiration Format

Both `--expire-at` and `--expire-in` are accepted by `kd-share-folder` and `kd-share-record`.

| Format | Example | Meaning |
|---|---|---|
| ISO datetime | `2027-06-01T00:00:00Z` | Exact UTC expiry |
| `never` | `never` | No expiration |
| Days | `30d` | 30 days from now |
| Hours | `24h` | 24 hours from now |
| Minutes | `30mi` | 30 minutes from now |
| Months | `6mo` | 6 months from now |
| Years | `1y` | 1 year from now |

---

## Troubleshooting

| Error | Likely cause | Fix |
|---|---|---|
| `Folder not found` | Local cache is stale | Run `sync-down` then retry |
| `Record not found in KeeperDrive cache` | Cache is stale | Run `sync-down` then retry |
| `User not found` | Wrong email or user not in enterprise | Check email; run `enterprise-down` |
| `Record has no decrypted key` | Sync incomplete | Run `sync-down` |
| `Maximum 100 folders per invocation` | Too many folders passed | Split into batches of ≤ 100 |
| `Maximum 500 records per invocation` | Too many records to `kd-rm` | Split into batches of ≤ 500 |

---

*Document version: 2.0 — March 2026*  
*Reflects the current 19-command set (v3 API)*
