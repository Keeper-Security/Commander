# KeeperDrive Commands

## Commands

KeeperDrive commands manage folders, records, sharing, and permissions using the Keeper v3 API. All commands are prefixed with `kd-` and require authentication and a synced vault.

To get help on a particular command, run:

`help <command>`


| Command                                                 | Description                                                         |
| ------------------------------------------------------- | ------------------------------------------------------------------- |
| `[kd-mkdir]`                                            | Create a new KeeperDrive folder                                     |
| `[kd-rndir]`                                            | Rename a folder, change its color, or update permission inheritance |
| `[kd-list]`                                             | List KeeperDrive folders and records                                |
| `[kd-rmdir]`                                            | Remove one or more KeeperDrive folders                              |
| `[kd-share-folder]`                                     | Grant or remove a user's access to a folder                         |
| `[kd-record-add]`                                       | Create a new KeeperDrive record                                     |
| `[kd-record-update]`                                    | Update an existing KeeperDrive record                               |
| `[kd-rm]`                                               | Remove (trash or unlink) one or more KeeperDrive records            |
| `[kd-ln]`                                               | Link a record into a KeeperDrive folder                             |
| `[kd-shortcut](#kd-shortcut-command)`                   | Manage records that appear in more than one folder                  |
| `[kd-share-record](#kd-share-record-command)`           | Grant, update, or revoke a user's access to a record                |
| `[kd-record-permission](#kd-record-permission-command)` | Bulk-update sharing permissions across records in a folder          |
| `[kd-transfer-record](#kd-transfer-record-command)`     | Transfer record ownership to another user                           |
| `[kd-record-details](#kd-record-details-command)`       | Get metadata for one or more records                                |
| `[kd-get](#kd-get-command)`                             | Show full details for a record or folder                            |


**Permission roles** (used across folder and record sharing commands):


| Role                    | Description                                   |
| ----------------------- | --------------------------------------------- |
| `viewer`                | Read-only access                              |
| `shared-manager`        | Can manage access grants                      |
| `content-manager`       | Can add/edit records                          |
| `content-share-manager` | Can add/remove/edit records and manage access |
| `full-manager`          | Full control                                  |


---

### kd-mkdir command:

**Command:** `kd-mkdir`

**Detail:** Create a single KeeperDrive folder. `/` is a reserved character; use `//` to embed a literal slash in a folder name.

**Parameters:**

Folder name (nested paths are not supported — create one folder at a time)

**Switches:**

`--color <COLOR>` Folder color: `none` `red` `orange` `yellow` `green` `blue` `gray`

`--no-inherit` Do not inherit parent folder permissions

**Examples:**

```
kd-mkdir "My Projects"
kd-mkdir "Sensitive" --color red --no-inherit
kd-mkdir "Reports//2026"
```

1. Create a single folder at the vault root (or under the current folder when navigated into one)
2. Create a folder with red color and no permission inheritance from parent
3. Create a folder whose name literally contains a slash (`Reports/2026`); `//` escapes a literal `/`

---

### kd-rndir command:

**Command:** `kd-rndir`

**Detail:** Rename a folder, change its color, or update its permission-inheritance setting. At least one of `--name`, `--color`, `--inherit`, or `--no-inherit` is required.

**Parameters:**

Folder UID, name, or path

**Switches:**

`-n NAME`, `--name NAME` New folder name

`--color <COLOR>` New color: `none` `red` `orange` `yellow` `green` `blue` `gray`

`--inherit` Enable permission inheritance from parent folder

`--no-inherit` Disable permission inheritance from parent folder

`-q`, `--quiet` Suppress confirmation message

**Examples:**

```
kd-rndir "Old Name" --name "New Name"
kd-rndir abc123 --color blue
kd-rndir abc123 --name "Archive Q4" --color gray --inherit
kd-rndir abc123 --name "Finance" -q
```

1. Rename a folder by its current name
2. Change a folder's color using its UID
3. Rename, recolor, and enable permission inheritance in one command
4. Rename a folder silently with no confirmation output

---

### kd-list command:

**Command:** `kd-list`

**Detail:** List KeeperDrive folders and records from the local cache. If neither `--folders` nor `--records` is specified, both are shown. Each row reports whether the item is shared (and to how many non-owner accessors).

**Switches:**

`--folders` Show only folders

`--records` Show only records

`-v`, `--verbose` Show detailed information including parent UID and folder location

`--format <{table, csv, json}>` Choose the format of the output (default: `table`)

`--output <FILE>` Write output to file (ignored for `table` format)

**Examples:**

```
kd-list
kd-list --folders --verbose
kd-list --records --format json --output records.json
kd-list --format csv --output export.csv
```

1. List all KeeperDrive folders and records
2. List only folders with detailed parent/location information
3. List only records and export to a JSON file
4. Export full listing to a CSV file

---

### kd-rmdir command:

**Command:** `kd-rmdir`

**Detail:** Remove one or more KeeperDrive folders. Always shows a preview of the impact before asking for confirmation.

**Parameters:**

Folder UID(s) or name(s) to remove (max 100 per invocation)

**Switches:**

`-o OP`, `--operation OP` Removal mode: `folder-trash` (default, recoverable) or `delete-permanent` (irreversible)

`-f`, `--force` Skip the confirmation prompt and execute immediately after preview

`--dry-run` Preview only — do not delete anything (mutually exclusive with `--force`)

`-q`, `--quiet` Suppress per-folder impact detail in the preview output

**Examples:**

```
kd-rmdir "Old Projects"
kd-rmdir abc123 --dry-run
kd-rmdir abc123 def456 --operation delete-permanent --force
kd-rmdir "Archive" --quiet
```

1. Move a folder to trash (recoverable) — prompts for confirmation after preview
2. Preview the deletion impact without committing any changes
3. Permanently delete two folders with no confirmation prompt
4. Delete a folder with minimal preview output

> **Warning:** `--operation delete-permanent` is irreversible. All sub-folders and records inside will be permanently destroyed.

---

### kd-share-folder command:

**Command:** `kd-share-folder`

**Detail:** Grant or remove a user's access to one or more KeeperDrive folders. The action is controlled by `--action` (default: `grant`).

**Parameters:**

Folder UID(s), name(s), or path(s)

**Switches:**

`-e EMAIL`, `--email EMAIL` Recipient email address. Repeatable: `-e user1@example.com -e user2@example.com`. Use `@existing` (or its alias `@current`) to target all current users in the folder (excluding yourself).

`-a ACTION`, `--action ACTION` `grant` (default — also updates existing shares) or `remove`

`-r ROLE`, `--role ROLE` Permission role (default: `viewer`). See permission roles table above.

`--expire-at TIMESTAMP` Expiration as ISO datetime `yyyy-MM-ddTHH:MM:SSZ` or `never`

`--expire-in PERIOD` Expiration as period: `30d` `6mo` `1y` `24h` `30mi` or `never` (mutually exclusive with `--expire-at`)

**Examples:**

```
kd-share-folder "My Projects" -e colleague@example.com
kd-share-folder abc123 -e manager@example.com -r full-manager
kd-share-folder abc123 -e temp@example.com -r viewer --expire-in 7d
kd-share-folder abc123 -e user@example.com -a remove
kd-share-folder abc123 def456 -e user1@example.com -e user2@example.com -r viewer
kd-share-folder "Team Folder" -e @existing -a remove
```

1. Grant default viewer access to a folder
2. Grant full-manager access using a folder UID
3. Grant viewer access that expires in 7 days
4. Remove a user's access to a folder
5. Grant viewer access to multiple folders and multiple users in one command
6. Remove all existing users from a folder at once

---

### kd-record-add command:

**Command:** `kd-record-add`

**Detail:** Create a new KeeperDrive record. Fields are specified using `type=value` or `type.label=value` dot notation. See `--syntax-help` for full field notation details.

**Switches:**

`-t TITLE`, `--title TITLE` Record title (required)

`-rt TYPE`, `--record-type TYPE` Record type, e.g. `login`, `general` (required)

`-n NOTES`, `--notes NOTES` Record notes

`--folder FOLDER` Folder UID or name to store the record (vault root if omitted)

`-f`, `--force` Ignore field-validation warnings

`--syntax-help` Display full field notation syntax help

**Examples:**

```
kd-record-add -t "Gmail" -rt login login=user@gmail.com password=Secret123
kd-record-add -t "Dev Server" -rt login --folder "Infrastructure" login=root password=Pass123 url=ssh://dev.example.com
kd-record-add -t "API Key" -rt general --folder "Secrets" "License ID"=9ACB123
kd-record-add --syntax-help
```

1. Create a login record at the vault root
2. Create a login record in a specific folder with multiple fields
3. Create a general record with a custom-labeled field
4. Display full field syntax help

---

### kd-record-update command:

**Command:** `kd-record-update`

**Detail:** Update an existing KeeperDrive record's title, type, notes, or field values. One or more record UIDs or titles must be specified with `-r`.

**Switches:**

`-r UID`, `--record UID` Record UID or title (required). Repeatable: `-r uid1 -r uid2`

`-t TITLE`, `--title TITLE` New record title

`-rt TYPE`, `--record-type TYPE` New record type

`-n NOTES`, `--notes NOTES` Append or replace record notes

`-f`, `--force` Ignore field-validation warnings

`--syntax-help` Display full field notation syntax help

**Examples:**

```
kd-record-update -r rec123 -t "Updated Title"
kd-record-update -r rec123 password=NewPass123
kd-record-update -r rec123 -t "Production DB" -n "Rotated 2025-03-01" password=NewPass
kd-record-update -r rec123 -r rec456 -t "Shared Title"
```

1. Update only the title of a record
2. Update a single field value
3. Update title, notes, and a field value together
4. Apply the same title update to two records at once

---

### kd-rm command:

**Command:** `kd-rm`

**Detail:** Remove (trash or unlink) one or more KeeperDrive records. Always shows a preview before executing.

**Parameters:**

Record UID(s) or title(s) to remove (max 500 per invocation)

**Switches:**

`-f FOLDER`, `--folder FOLDER` Folder UID or name providing context for the operation (required when `--operation unlink`)

`-o OP`, `--operation OP` Removal mode (default: `owner-trash`)

`--force` Skip the confirmation prompt and execute after preview

`--dry-run` Preview only — do not delete anything (mutually exclusive with `--force`)

**Operation types:**


| Operation      | Effect                                                          |
| -------------- | --------------------------------------------------------------- |
| `owner-trash`  | Move record to owner's trash (recoverable) — default            |
| `folder-trash` | Remove record from a folder and trash it                        |
| `unlink`       | Remove record from a specific folder only — requires `--folder` |


**Examples:**

```
kd-rm rec123abc
kd-rm rec123abc --folder "Projects" --operation unlink
kd-rm rec123abc rec456def --dry-run
kd-rm rec123abc rec456def --force
kd-rm rec123abc --operation folder-trash --folder "Archive"
```

1. Trash a record (shows preview, then prompts for confirmation)
2. Unlink a record from a specific folder without deleting it
3. Preview the impact for two records without making any changes
4. Trash two records immediately with no prompt
5. Remove a record from a specific folder and send it to trash

---

### kd-ln command:

**Command:** `kd-ln`

**Detail:** Link a record into a KeeperDrive folder using short positional syntax. This adds the record to the folder without removing it from its current location.

**Parameters:**

`src` — Record UID or title

`dst` — Destination folder UID or name

**Examples:**

```
kd-ln rec123abc "My Projects"
kd-ln rec123abc abc123folder
```

1. Link a record by title into a folder by name
2. Link a record by UID into a folder by UID

---

### kd-shortcut command:

**Command:** `kd-shortcut`

**Detail:** Manage KeeperDrive records that appear in more than one folder. Supports two sub-commands: `list` and `keep`.

#### kd-shortcut list

List all records linked to more than one folder.

**Parameters:**

`target` — Optional record UID, title, or folder path to filter results

**Switches:**

`--format <{table, csv, json}>` Choose the format of the output (default: `table`)

`--output FILE` Write csv/json output to a file

**Examples:**

```
kd-shortcut list
kd-shortcut list "My Record"
kd-shortcut list "Projects" --format json
kd-shortcut list --format csv --output shortcuts.csv
```

1. List all records that appear in more than one folder
2. List shortcuts for a specific record by title
3. List shortcuts for records in a specific folder in JSON format
4. Export the full shortcuts list to a CSV file

#### kd-shortcut keep

Keep a record in exactly one folder, removing it from all others.

**Parameters:**

`target` — Record UID or title

`folder` — Folder UID or path to keep the record in (defaults to current folder)

**Switches:**

`-f`, `--force` Skip the confirmation prompt before removing shortcuts

**Examples:**

```
kd-shortcut keep rec123abc "My Projects"
kd-shortcut keep "My Record" "Preferred Folder" --force
```

1. Keep a record only in `My Projects`, removing it from all other folders (prompts for confirmation)
2. Remove shortcuts without a confirmation prompt

---

### kd-share-record command:

**Command:** `kd-share-record`

**Detail:** Grant, update, or revoke a user's access to a record. All three actions are handled by one command via `--action` (default: `grant`).

**Parameters:**

Record UID or folder UID (use with `-R` for bulk sharing across all records in a folder)

**Switches:**

`-e EMAIL`, `--email EMAIL` Recipient email address (required). Repeatable: `-e user1@example.com -e user2@example.com`

`-a ACTION`, `--action ACTION` `grant` (default — also updates existing shares), `revoke`, or `owner` (transfer ownership)

`-r ROLE`, `--role ROLE` Permission role. Required for `grant` action. See permission roles table above.

`-R`, `--recursive` Apply to all records in a folder and its sub-folders

`--contacts-only` Only share with known contacts already in your vault

`-f`, `--force` Skip confirmation prompts

`--dry-run` Display permission changes without committing them

`--expire-at TIMESTAMP` Expiration as ISO datetime or `never`

`--expire-in PERIOD` Expiration as period: `30d` `6mo` `1y` `24h` `30mi` or `never` (mutually exclusive with `--expire-at`)

**Examples:**

```
kd-share-record rec123abc -e colleague@example.com -r viewer
kd-share-record rec123abc -e user1@example.com -e user2@example.com -r viewer
kd-share-record rec123abc -e colleague@example.com -a revoke
kd-share-record rec123abc -e temp@example.com -r viewer --expire-in 30d
kd-share-record folderabc -e team@example.com -r viewer -R
kd-share-record rec123abc -e newowner@example.com -a owner
kd-share-record rec123abc -e user@example.com -r full-manager --dry-run
```

1. Grant viewer access to a record
2. Grant viewer access to multiple recipients at once
3. Revoke a user's access to a record
4. Grant viewer access that expires in 30 days
5. Bulk share all records in a folder (and sub-folders) with a team
6. Transfer ownership of a record to another user
7. Preview permission changes without committing them

> **Note:** `-a grant` on a record that is already shared with the recipient will automatically update their existing share to the new role. `-a owner` transfers record ownership — only one recipient is allowed and you will lose access to the record after the transfer.

---

### kd-record-permission command:

**Command:** `kd-record-permission`

**Detail:** Bulk-update sharing permissions across all records in a folder and optionally its sub-folders. Always shows a change plan before executing.

**Parameters:**

`folder` — Folder UID or path (optional; omit to target vault root)

**Switches:**

`-a ACTION`, `--action ACTION` `grant` or `revoke` (required)

`-r ROLE`, `--role ROLE` Role to grant, or role to filter when revoking. Required for `grant` action.

`-R`, `--recursive` Apply to all sub-folders recursively

`-f`, `--force` Apply changes without a confirmation prompt

`--dry-run` Preview changes without committing them

**Examples:**

```
kd-record-permission -a grant -r viewer "My Projects" --dry-run
kd-record-permission -a revoke -r viewer "Archive" -R --force
kd-record-permission -a grant -r viewer
kd-record-permission -a revoke "Old Folder" --dry-run
```

1. Preview: grant viewer permission to all records in `My Projects`
2. Revoke viewer permission from all records in `Archive` and its sub-folders without prompting
3. Grant viewer permission to all records at the vault root level
4. Preview what would be revoked across all records in a folder

---

### kd-transfer-record command:

**Command:** `kd-transfer-record`

**Detail:** Transfer record ownership to another user. After transfer you permanently lose access to the record. This cannot be easily reversed.

**Parameters:**

`record_uids` — UID(s) of the record(s) to transfer

`new_owner_email` — Email address of the new owner

**Examples:**

```
kd-transfer-record rec123abc newowner@example.com
kd-transfer-record rec123abc rec456def newowner@example.com
```

1. Transfer ownership of a single record to another user
2. Transfer ownership of multiple records to the same new owner

> **Warning:** After the transfer you will no longer have access to these records.

---

### kd-record-details command:

**Command:** `kd-record-details`

**Detail:** Get metadata (title, type, version, revision) for one or more records.

**Parameters:**

One or more record UIDs or titles

**Switches:**

`--format <{table, json}>` Choose the format of the output (default: `table`)

**Examples:**

```
kd-record-details rec123abc
kd-record-details rec123abc rec456def rec789ghi
kd-record-details rec123abc --format json
```

1. Show metadata for a single record
2. Show metadata for multiple records at once
3. Show metadata for a record in JSON format

---

### kd-get command:

**Command:** `kd-get`

**Detail:** Show full details for a KeeperDrive record or folder by UID or title — including fields, notes, and access list.

**Parameters:**

Record UID, folder UID, or title/name

**Switches:**

`--format <{detail, json}>` Choose the format of the output: `detail` (default) or `json`

`-v`, `--verbose` Show full per-permission flag breakdown for each accessor

`--unmask` Reveal masked field values (passwords, secrets)

**Examples:**

```
kd-get rec123abc
kd-get "Gmail Account" --unmask
kd-get abc123folder --verbose
kd-get rec123abc --format json
kd-get rec123abc --format json --verbose
```

1. Show the details of a specific record
2. Show a record's details and reveal its masked password field
3. Show a folder's details with full permission flags per accessor
4. Show a record's details in JSON format
5. Show a record in JSON format with full per-accessor permission flags

---

## Quick Reference

### Folder commands


| Command           | Short description             |
| ----------------- | ----------------------------- |
| `kd-mkdir`        | Create a folder               |
| `kd-rndir`        | Rename / recolor a folder     |
| `kd-list`         | List folders and records      |
| `kd-rmdir`        | Remove folder(s)              |
| `kd-share-folder` | Grant or remove folder access |


### Record commands


| Command            | Short description                               |
| ------------------ | ----------------------------------------------- |
| `kd-record-add`    | Create a record                                 |
| `kd-record-update` | Update a record                                 |
| `kd-rm`            | Remove / trash / unlink a record                |
| `kd-ln`            | Link a record into a folder                     |
| `kd-shortcut list` | List multi-folder records                       |
| `kd-shortcut keep` | Keep record in one folder, unlink from the rest |


### Sharing commands


| Command                | Short description                               |
| ---------------------- | ----------------------------------------------- |
| `kd-share-record`      | Grant / revoke / transfer ownership of a record |
| `kd-record-permission` | Bulk update sharing across a folder             |
| `kd-transfer-record`   | Transfer record ownership                       |
| `kd-share-folder`      | Grant or revoke folder access                   |


### Inspection commands


| Command             | Short description                  |
| ------------------- | ---------------------------------- |
| `kd-get`            | Show full record or folder details |
| `kd-record-details` | Get record metadata (batch)        |


---

## Common Workflows

### Set up a shared project folder

```bash
# 1. Create folder
kd-mkdir "Client Projects" --color blue

# 2. Add a record
kd-record-add -t "Client Portal" -rt login --folder "Client Projects" \
  login=admin@client.com password=Secret123 url=https://portal.client.com

# 3. Share the folder with a colleague
kd-share-folder "Client Projects" -e colleague@company.com -r content-manager

# 4. Verify the listing
kd-list --folders --verbose
```

### Share a record with time-limited access

```bash
# Grant 30-day viewer access
kd-share-record rec123abc -e contractor@external.com -r viewer --expire-in 30d

# Preview what will change (dry-run first)
kd-share-record rec123abc -e contractor@external.com -r full-manager --dry-run

# Revoke when done
kd-share-record rec123abc -e contractor@external.com -a revoke
```

### Clean up multi-folder shortcuts

```bash
# Find all records in multiple folders
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

# Or permanently delete (irreversible)
kd-rmdir "Old Archive" --operation delete-permanent --force
```

### Bulk-revoke permissions across a folder tree

```bash
# Preview what will be revoked
kd-record-permission -a revoke -r viewer "Archive" -R --dry-run

# Apply without prompting
kd-record-permission -a revoke -r viewer "Archive" -R --force
```

---

## Expiration Format

Both `--expire-at` and `--expire-in` are accepted by `kd-share-folder` and `kd-share-record`. They are mutually exclusive — use one or the other.


| Format       | Example                | Meaning             |
| ------------ | ---------------------- | ------------------- |
| ISO datetime | `2027-06-01T00:00:00Z` | Exact UTC expiry    |
| `never`      | `never`                | No expiration       |
| Days         | `30d`                  | 30 days from now    |
| Hours        | `24h`                  | 24 hours from now   |
| Minutes      | `30mi`                 | 30 minutes from now |
| Months       | `6mo`                  | 6 months from now   |
| Years        | `1y`                   | 1 year from now     |


---

## Troubleshooting


| Error                                                   | Likely cause                                      | Fix                                                                            |
| ------------------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------------------------ |
| `Folder not found`                                      | Local cache is stale                              | Run `sync-down` then retry                                                     |
| `Record not found in KeeperDrive cache`                 | Cache is stale                                    | Run `sync-down` then retry                                                     |
| `User not found`                                        | Wrong email or user not in enterprise             | Check email; run `enterprise-down`                                             |
| `Record has no decrypted key`                           | Sync incomplete                                   | Run `sync-down`                                                                |
| `Maximum 100 folders per invocation`                    | Too many folders passed to `kd-rmdir`             | Split into batches of ≤ 100                                                    |
| `Maximum 500 records per invocation`                    | Too many records passed to `kd-rm`                | Split into batches of ≤ 500                                                    |
| `--folder is required when --operation is unlink`       | Missing `--folder` for unlink                     | Add `--folder <folder>` to the command                                         |
| `Ownership can only be transferred to a single account` | Multiple `-e` with `-a owner`                     | Specify only one `-e` email when using `-a owner`                              |
| `You do not have permission to edit this folder.`       | Insufficient folder rights for `kd-rndir`         | Ask the folder owner / a manager to grant the `update_setting` permission      |
| `You do not have permission to share this folder.`      | Insufficient folder rights for `kd-share-folder`  | Ask the folder owner / a manager to grant the `update_access` permission       |
| `You do not have permission to delete this folder.`     | Insufficient folder rights for `kd-rmdir`         | Ask the folder owner / a manager to grant the `delete` permission              |
| `You do not have edit permissions on this record.`      | Insufficient record rights for `kd-record-update` | Ask the record owner to grant the `edit` permission                            |
| `You do not have permission to share this record.`      | Insufficient record rights for `kd-share-record`  | Ask the record owner / a share-manager to grant the `update_access` permission |
| `You do not have permission to delete this record.`     | Insufficient record rights for `kd-rm`            | Ask the record owner to grant the `delete` permission                          |


---

