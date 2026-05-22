# KeeperDrive Commands

## Commands

KeeperDrive commands manage folders, records, sharing, and permissions using the Keeper v3 API. All commands are prefixed with `nsf-` and require authentication and a synced vault.

To get help on a particular command, run:

`help <command>`


| Command                  | Description                                                         |
| ------------------------ | ------------------------------------------------------------------- |
| `[nsf-mkdir]`             | Create a new KeeperDrive folder                                     |
| `[nsf-rndir]`             | Rename a folder or change its color                                 |
| `[nsf-list]`              | List KeeperDrive folders and records                                |
| `[nsf-rmdir]`             | Remove one or more KeeperDrive folders                              |
| `[nsf-share-folder]`      | Grant or remove a user's access to a folder                         |
| `[nsf-record-add]`        | Create a new KeeperDrive record                                     |
| `[nsf-record-update]`     | Update an existing KeeperDrive record                               |
| `[nsf-rm]`                | Remove (trash or unlink) one or more KeeperDrive records            |
| `[nsf-ln]`                | Link a record into a KeeperDrive folder                             |
| `[nsf-shortcut]`          | Manage records that appear in more than one folder                  |
| `[nsf-share-record]`      | Grant, update, or revoke a user's access to a record                |
| `[nsf-record-permission]` | Bulk-update sharing permissions across records in a folder          |
| `[nsf-transfer-record]`   | Transfer record ownership to another user                           |
| `[nsf-record-details]`    | Get metadata for records                                |
| `[nsf-get]`               | Show full details for a record or folder                            |


**Permission roles** (used across folder and record sharing commands):


| Role                    | Description                                   |
| ----------------------- | --------------------------------------------- |
| `viewer`                | Read-only access                              |
| `share-manager`         | Can manage access grants                      |
| `content-manager`       | Can add/edit records                          |
| `content-share-manager` | Can add/remove/edit records and manage access |
| `full-manager`          | Full control                                  |


---

### nsf-mkdir command:

**Command:** `nsf-mkdir`

**Detail:** Create a single KeeperDrive folder. `/` is a reserved character; use `//` to embed a literal slash in a folder name.

**Parameters:**

Folder name (nested paths are not supported — create one folder at a time)

**Switches:**

`--color <COLOR>` Folder color: `none` `red` `orange` `yellow` `green` `blue` `gray`

`--no-inherit` Do not inherit parent folder permissions

**Examples:**

```
nsf-mkdir "My Projects"
nsf-mkdir "Sensitive" --color red --no-inherit
nsf-mkdir "Reports//2026"
```

1. Create a single folder at the vault root (or under the current folder when navigated into one)
2. Create a folder with red color and no permission inheritance from parent
3. Create a folder whose name literally contains a slash (`Reports/2026`); `//` escapes a literal `/`

---

### nsf-rndir command:

**Command:** `nsf-rndir`

**Detail:** Rename a folder or change its color. At least one of `--name` or `--color` is required.

**Parameters:**

Folder UID, name, or path

**Switches:**

`-n NAME`, `--name NAME` New folder name

`--color <COLOR>` New color: `none` `red` `orange` `yellow` `green` `blue` `gray`



`-q`, `--quiet` Suppress confirmation message

**Examples:**

```
nsf-rndir "Old Name" --name "New Name"
nsf-rndir abc123 --color blue
nsf-rndir abc123 --name "Archive Q4" --color gray
nsf-rndir abc123 --name "Finance" -q
```

1. Rename a folder by its current name
2. Change a folder's color using its UID
3. Rename and recolor a folder in one command
4. Rename a folder silently with no confirmation output

---

### nsf-list command:

**Command:** `nsf-list`

**Detail:** List KeeperDrive folders and records from the local cache. If neither `--folders` nor `--records` is specified, both are shown. Each row reports whether the item is shared (and to how many non-owner accessors).

**Switches:**

`--folders` Show only folders

`--records` Show only records

`--format <{table, csv, json}>` Choose the format of the output (default: `table`)

`--output <FILE>` Write output to file (ignored for `table` format)

**Examples:**

```
nsf-list
nsf-list --records --format json --output records.json
nsf-list --format csv --output export.csv
```

1. List all KeeperDrive folders and records
2. List only folders with detailed parent/location information
3. List only records and export to a JSON file
4. Export full listing to a CSV file

---

### nsf-rmdir command:

**Command:** `nsf-rmdir`

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
nsf-rmdir "Old Projects"
nsf-rmdir abc123 --dry-run
nsf-rmdir abc123 def456 --operation delete-permanent --force
nsf-rmdir "Archive" --quiet
```

1. k
2. Preview the deletion impkdact without committing any changes
3. Permanently delete two folders with no confirmation prompt
4. Delete a folder with minimal preview output

> **Warning:** `--operation delete-permanent` is irreversible. All sub-folders and records inside will be permanently destroyed.

---

### nsf-share-folder command:

**Command:** `nsf-share-folder`

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
nsf-share-folder "My Projects" -e colleague@example.com
nsf-share-folder abc123 -e manager@example.com -r full-manager
nsf-share-folder abc123 -e temp@example.com -r viewer --expire-in 7d
nsf-share-folder abc123 -e user@example.com -a remove
nsf-share-folder abc123 def456 -e user1@example.com -e user2@example.com -r viewer
nsf-share-folder "Team Folder" -e @existing -a remove
```

1. Grant default viewer access to a folder
2. Grant full-manager access using a folder UID
3. Grant viewer access that expires in 7 days
4. Remove a user's access to a folder
5. Grant viewer access to multiple folders and multiple users in one command
6. Remove all existing users from a folder at once

---

### nsf-record-add command:

**Command:** `nsf-record-add`

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
nsf-record-add -t "Gmail" -rt login login=user@gmail.com password=Secret123
nsf-record-add -t "Dev Server" -rt login --folder "Infrastructure" login=root password=Pass123 url=ssh://dev.example.com
nsf-record-add -t "API Key" -rt general --folder "Secrets" "License ID"=9ACB123
nsf-record-add --syntax-help
```

1. Create a login record at the vault root
2. Create a login record in a specific folder with multiple fields
3. Create a general record with a custom-labeled field
4. Display full field syntax help

---

### nsf-record-update command:

**Command:** `nsf-record-update`

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
nsf-record-update -r rec123 -t "Updated Title"
nsf-record-update -r rec123 password=NewPass123
nsf-record-update -r rec123 -t "Production DB" -n "Rotated 2025-03-01" password=NewPass
nsf-record-update -r rec123 -r rec456 -t "Shared Title"
```

1. Update only the title of a record
2. Update a single field value
3. Update title, notes, and a field value together
4. Apply the same title update to two records at once

---

### nsf-rm command:

**Command:** `nsf-rm`

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
nsf-rm rec123abc
nsf-rm rec123abc --folder "Projects" --operation unlink
nsf-rm rec123abc rec456def --dry-run
nsf-rm rec123abc rec456def --force
nsf-rm rec123abc --operation folder-trash --folder "Archive"
```

1. Trash a record (shows preview, then prompts for confirmation)
2. Unlink a record from a specific folder without deleting it
3. Preview the impact for two records without making any changes
4. Trash two records immediately with no prompt
5. Remove a record from a specific folder and send it to trash

---

### nsf-ln command:

**Command:** `nsf-ln`

**Detail:** Link a record into a KeeperDrive folder using short positional syntax. This adds the record to the folder without removing it from its current location.

**Parameters:**

`src` — Record UID or title

`dst` — Destination folder UID or name

**Examples:**

```
nsf-ln rec123abc "My Projects"
nsf-ln rec123abc abc123folder
```

1. Link a record by title into a folder by name
2. Link a record by UID into a folder by UID

---

### nsf-shortcut command:

**Command:** `nsf-shortcut`

**Detail:** Manage KeeperDrive records that appear in more than one folder. Supports two sub-commands: `list` and `keep`.

#### nsf-shortcut list

List all records linked to more than one folder.

**Parameters:**

`target` — Optional record UID, title, or folder path to filter results

**Switches:**

`--format <{table, csv, json}>` Choose the format of the output (default: `table`)

`--output FILE` Write csv/json output to a file

**Examples:**

```
nsf-shortcut list
nsf-shortcut list "My Record"
nsf-shortcut list "Projects" --format json
nsf-shortcut list --format csv --output shortcuts.csv
```

1. List all records that appear in more than one folder
2. List shortcuts for a specific record by title
3. List shortcuts for records in a specific folder in JSON format
4. Export the full shortcuts list to a CSV file

#### nsf-shortcut keep

Keep a record in exactly one folder, removing it from all others.

**Parameters:**

`target` — Record UID or title

`folder` — Folder UID or path to keep the record in (defaults to current folder)

**Switches:**

`-f`, `--force` Skip the confirmation prompt before removing shortcuts

**Examples:**

```
nsf-shortcut keep rec123abc "My Projects"
nsf-shortcut keep "My Record" "Preferred Folder" --force
```

1. Keep a record only in `My Projects`, removing it from all other folders (prompts for confirmation)
2. Remove shortcuts without a confirmation prompt

---

### nsf-share-record command:

**Command:** `nsf-share-record`

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
nsf-share-record rec123abc -e colleague@example.com -r viewer
nsf-share-record rec123abc -e user1@example.com -e user2@example.com -r viewer
nsf-share-record rec123abc -e colleague@example.com -a revoke
nsf-share-record rec123abc -e temp@example.com -r viewer --expire-in 30d
nsf-share-record folderabc -e team@example.com -r viewer -R
nsf-share-record rec123abc -e newowner@example.com -a owner
nsf-share-record rec123abc -e user@example.com -r full-manager --dry-run
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

### nsf-record-permission command:

**Command:** `nsf-record-permission`

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
nsf-record-permission -a grant -r viewer "My Projects" --dry-run
nsf-record-permission -a revoke -r viewer "Archive" -R --force
nsf-record-permission -a grant -r viewer
nsf-record-permission -a revoke "Old Folder" --dry-run
```

1. Preview: grant viewer permission to all records in `My Projects`
2. Revoke viewer permission from all records in `Archive` and its sub-folders without prompting
3. Grant viewer permission to all records at the vault root level
4. Preview what would be revoked across all records in a folder

---

### nsf-transfer-record command:

**Command:** `nsf-transfer-record`

**Detail:** Transfer record ownership to another user. After transfer you permanently lose access to the record. This cannot be easily reversed.

**Parameters:**

`record_uids` — UID(s) of the record(s) to transfer

`new_owner_email` — Email address of the new owner

**Examples:**

```
nsf-transfer-record rec123abc newowner@example.com
nsf-transfer-record rec123abc rec456def newowner@example.com
```

1. Transfer ownership of a single record to another user
2. Transfer ownership of multiple records to the same new owner

> **Warning:** After the transfer you will no longer have access to these records.

---

### nsf-record-details command:

**Command:** `nsf-record-details`

**Detail:** Get metadata (title, type, version, revision) for one or more records.

**Parameters:**

One or more record UIDs or titles

**Switches:**

`--format <{table, json}>` Choose the format of the output (default: `table`)

**Examples:**

```
nsf-record-details rec123abc
nsf-record-details rec123abc rec456def rec789ghi
nsf-record-details rec123abc --format json
```

1. Show metadata for a single record
2. Show metadata for multiple records at once
3. Show metadata for a record in JSON format

---

### nsf-get command:

**Command:** `nsf-get`

**Detail:** Show full details for a KeeperDrive record or folder by UID or title — including fields, notes, and access list.

**Parameters:**

Record UID, folder UID, or title/name

**Switches:**

`--format <{detail, json}>` Choose the format of the output: `detail` (default) or `json`

`-v`, `--verbose` Show full per-permission flag breakdown for each accessor

`--unmask` Reveal masked field values (passwords, secrets)

**Examples:**

```
nsf-get rec123abc
nsf-get "Gmail Account" --unmask
nsf-get abc123folder --verbose
nsf-get rec123abc --format json
nsf-get rec123abc --format json --verbose
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
| `nsf-mkdir`        | Create a folder               |
| `nsf-rndir`        | Rename / recolor a folder     |
| `nsf-list`         | List folders and records      |
| `nsf-rmdir`        | Remove folder(s)              |
| `nsf-share-folder` | Grant or remove folder access |


### Record commands


| Command            | Short description                               |
| ------------------ | ----------------------------------------------- |
| `nsf-record-add`    | Create a record                                 |
| `nsf-record-update` | Update a record                                 |
| `nsf-rm`            | Remove / trash / unlink a record                |
| `nsf-ln`            | Link a record into a folder                     |
| `nsf-shortcut list` | List multi-folder records                       |
| `nsf-shortcut keep` | Keep record in one folder, unlink from the rest |


### Sharing commands


| Command                | Short description                               |
| ---------------------- | ----------------------------------------------- |
| `nsf-share-record`      | Grant / revoke / transfer ownership of a record |
| `nsf-record-permission` | Bulk update sharing across a folder             |
| `nsf-transfer-record`   | Transfer record ownership                       |
| `nsf-share-folder`      | Grant or revoke folder access                   |


### Inspection commands


| Command             | Short description                  |
| ------------------- | ---------------------------------- |
| `nsf-get`            | Show full record or folder details |
| `nsf-record-details` | Get record metadata (batch)        |


---

## Common Workflows

### Set up a shared project folder

```bash
# 1. Create folder
nsf-mkdir "Client Projects" --color blue

# 2. Add a record
nsf-record-add -t "Client Portal" -rt login --folder "Client Projects" \
  login=admin@client.com password=Secret123 url=https://portal.client.com

# 3. Share the folder with a colleague
nsf-share-folder "Client Projects" -e colleague@company.com -r content-manager

# 4. Verify the listing
nsf-list --folders
```

### Share a record with time-limited access

```bash
# Grant 30-day viewer access
nsf-share-record rec123abc -e contractor@external.com -r viewer --expire-in 30d

# Preview what will change (dry-run first)
nsf-share-record rec123abc -e contractor@external.com -r full-manager --dry-run

# Revoke when done
nsf-share-record rec123abc -e contractor@external.com -a revoke
```

### Clean up multi-folder shortcuts

```bash
# Find all records in multiple folders
nsf-shortcut list

# Keep a record in only one folder
nsf-shortcut keep "My Record" "Preferred Folder"
```

### Safely remove a folder

```bash
# Preview impact
nsf-rmdir "Old Archive" --dry-run

# Trash (recoverable)
nsf-rmdir "Old Archive"

# Or permanently delete (irreversible)
nsf-rmdir "Old Archive" --operation delete-permanent --force
```

### Bulk-revoke permissions across a folder tree

```bash
# Preview what will be revoked
nsf-record-permission -a revoke -r viewer "Archive" -R --dry-run

# Apply without prompting
nsf-record-permission -a revoke -r viewer "Archive" -R --force
```

---

## Expiration Format

Both `--expire-at` and `--expire-in` are accepted by `nsf-share-folder` and `nsf-share-record`. They are mutually exclusive — use one or the other.


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

---

