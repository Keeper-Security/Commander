# KeeperDrive Commands Documentation

## Overview

KeeperDrive commands provide a comprehensive interface for managing folders and records using the Keeper v3 API. These commands allow you to create, update, share, and manage your Keeper vault through the command line.

**Note:** All KeeperDrive commands use the v3 API and require proper authentication and synchronization with your Keeper vault.

---

## Table of Contents

1. [Folder Management](#folder-management)
   - [keeper-drive-mkdir](#keeper-drive-mkdir)
   - [keeper-drive-update-folder](#keeper-drive-update-folder)
   - [keeper-drive-list](#keeper-drive-list)

2. [Folder Access Management](#folder-access-management)
   - [keeper-drive-grant-access](#keeper-drive-grant-access)
   - [keeper-drive-update-access](#keeper-drive-update-access)
   - [keeper-drive-revoke-access](#keeper-drive-revoke-access)

3. [Record Management](#record-management)
   - [keeper-drive-add-record](#keeper-drive-add-record)
   - [keeper-drive-update-record](#keeper-drive-update-record)
   - [keeper-drive-get-record-details](#keeper-drive-get-record-details)

4. [Record Sharing](#record-sharing)
   - [keeper-drive-share-record](#keeper-drive-share-record)
   - [keeper-drive-update-record-share](#keeper-drive-update-record-share)
   - [keeper-drive-unshare-record](#keeper-drive-unshare-record)
   - [keeper-drive-get-record-access](#keeper-drive-get-record-access)

5. [Record Ownership](#record-ownership)
   - [keeper-drive-transfer-record](#keeper-drive-transfer-record)

6. [Folder-Record Management](#folder-record-management)
   - [keeper-drive-add-record-to-folder](#keeper-drive-add-record-to-folder)
   - [keeper-drive-remove-record-from-folder](#keeper-drive-remove-record-from-folder)
   - [keeper-drive-move-record](#keeper-drive-move-record)

---

## Folder Management

### keeper-drive-mkdir

Create a new KeeperDrive folder using the v3 API.

**Syntax:**
```bash
keeper-drive-mkdir <folder_name> [options]
```

**Parameters:**
- `<folder_name>` (required): Name of the folder to create

**Options:**
- `--parent <parent_uid>`: Parent folder UID (omit to create at root level)
- `--color <color>`: Folder color
  - Choices: `none`, `red`, `orange`, `yellow`, `green`, `blue`, `purple`, `pink`, `gray`
- `--no-inherit`: Do not inherit parent folder permissions

**Examples:**

1. Create a folder at root level:
```bash
keeper-drive-mkdir "My Projects"
```

2. Create a folder with a specific color:
```bash
keeper-drive-mkdir "Important Documents" --color red
```

3. Create a subfolder under an existing folder:
```bash
keeper-drive-mkdir "Q1 Reports" --parent abc123def456
```

4. Create a folder without inheriting permissions:
```bash
keeper-drive-mkdir "Private Files" --no-inherit
```

**Output:**
```
✓ Folder 'My Projects' created successfully at root
  Folder UID: xyz789abc123
```

---

### keeper-drive-update-folder

Update an existing KeeperDrive folder's properties.

**Syntax:**
```bash
keeper-drive-update-folder <folder_uid> [options]
```

**Parameters:**
- `<folder_uid>` (required): Folder UID, name, or path to update

**Options:**
- `--name <new_name>`: New folder name
- `--color <color>`: New folder color
  - Choices: `none`, `red`, `orange`, `yellow`, `green`, `blue`, `purple`, `pink`, `gray`
- `--inherit`: Set folder to inherit parent permissions
- `--no-inherit`: Set folder to not inherit parent permissions

**Note:** At least one update option must be provided.

**Examples:**

1. Rename a folder:
```bash
keeper-drive-update-folder xyz789abc123 --name "Renamed Folder"
```

2. Change folder color:
```bash
keeper-drive-update-folder xyz789abc123 --color blue
```

3. Update multiple properties:
```bash
keeper-drive-update-folder xyz789abc123 --name "New Name" --color green --inherit
```

4. Remove folder color:
```bash
keeper-drive-update-folder xyz789abc123 --color none
```

**Output:**
```
✓ Folder updated successfully
  Folder UID: xyz789abc123
  New name: Renamed Folder
  New color: blue
  Inherit permissions: True
```

**Tips:**
- If folder is not found, try running `sync-down` first to refresh your local cache
- You can use folder name or path instead of UID for easier access

---

### keeper-drive-list

List KeeperDrive folders and records from your vault.

**Syntax:**
```bash
keeper-drive-list [options]
```

**Options:**
- `--folders`: Show only folders
- `--records`: Show only records
- `--verbose`, `-v`: Show detailed information
- `--permissions`, `-p`: Show permissions and access information for records and folders

**Note:** If neither `--folders` nor `--records` is specified, both will be shown.

**Examples:**

1. List all folders and records:
```bash
keeper-drive-list
```

2. List only folders:
```bash
keeper-drive-list --folders
```

3. List only records with detailed information:
```bash
keeper-drive-list --records --verbose
```

4. Show folders with permission information:
```bash
keeper-drive-list --folders --permissions
```

5. Show everything with full details and permissions:
```bash
keeper-drive-list -v -p
```

**Output:**
```
=== Keeper Drive Folders ===

Folder: My Projects
  UID: xyz789abc123
  Parent: root
  Color: blue
  Has Key: ✓
  Owner: user@example.com
  Shared With: 2 entities
    - User: colleague@example.com - VIEWER (Can view folder)
    - User: manager@example.com - MANAGER (Full management permissions)

=== Keeper Drive Records ===

Record: Login Credentials
  UID: rec123abc456
  Type: login
  Version: 3
  Revision: 5
  Has Key: ✓
  Owner: user@example.com
  Shared With: 1 user
    - colleague@example.com: VIEWER (Can view record)

Summary:
  Keeper Drive folders: 10
  Keeper Drive records: 25
```

---

## Folder Access Management

### keeper-drive-grant-access

Grant a user access to a KeeperDrive folder.

**Syntax:**
```bash
keeper-drive-grant-access --folder <folder_uid> --user <user_email_or_uid> [options]
```

**Parameters:**
- `--folder <folder_uid>` (required): Folder UID, name, or path
- `--user <user_email_or_uid>` (required): User email address or UID to grant access to

**Options:**
- `--role <role>`: Access role (default: `viewer`)
  - Choices: `viewer`, `contributor`, `content_manager`, `manager`
- `--expire <time>`: Expiration time
  - Unix timestamp in seconds, or
  - Relative time: `30d` (30 days), `24h` (24 hours), `30mi` (30 minutes)

**Access Roles:**
- **viewer**: Can view folder contents
- **contributor**: Can view and edit folder contents
- **content_manager**: Can manage folder content
- **manager**: Full management permissions including sharing

**Examples:**

1. Grant viewer access to a folder:
```bash
keeper-drive-grant-access --folder xyz789abc123 --user colleague@example.com
```

2. Grant manager access:
```bash
keeper-drive-grant-access --folder xyz789abc123 --user manager@example.com --role manager
```

3. Grant temporary access that expires in 7 days:
```bash
keeper-drive-grant-access --folder xyz789abc123 --user temp@example.com --role viewer --expire 7d
```

4. Grant access with expiration in 24 hours:
```bash
keeper-drive-grant-access --folder xyz789abc123 --user contractor@example.com --role contributor --expire 24h
```

**Output:**
```
✓ Access granted successfully
  Folder: xyz789abc123
  User: colleague@example.com
  Role: viewer
  Expiration: 2025-11-12 14:30:00
```

---

### keeper-drive-update-access

Update a user's access permissions to a KeeperDrive folder.

**Syntax:**
```bash
keeper-drive-update-access --folder <folder_uid> --user <user_email_or_uid> [options]
```

**Parameters:**
- `--folder <folder_uid>` (required): Folder UID, name, or path
- `--user <user_email_or_uid>` (required): User email address or UID whose access to update

**Options:**
- `--role <role>`: New access role
  - Choices: `viewer`, `contributor`, `content_manager`, `manager`
- `--hidden <true|false>`: Hide the folder access

**Note:** At least one option (`--role` or `--hidden`) must be specified.

**Examples:**

1. Update user's role to manager:
```bash
keeper-drive-update-access --folder xyz789abc123 --user colleague@example.com --role manager
```

2. Hide folder from user's view:
```bash
keeper-drive-update-access --folder xyz789abc123 --user user@example.com --hidden true
```

3. Downgrade access from manager to viewer:
```bash
keeper-drive-update-access --folder xyz789abc123 --user user@example.com --role viewer
```

**Output:**
```
✓ Access updated successfully
  Folder: xyz789abc123
  User: colleague@example.com
  New Role: manager
```

---

### keeper-drive-revoke-access

Revoke a user's access from a KeeperDrive folder.

**Syntax:**
```bash
keeper-drive-revoke-access --folder <folder_uid> --user <user_email_or_uid>
```

**Parameters:**
- `--folder <folder_uid>` (required): Folder UID, name, or path
- `--user <user_email_or_uid>` (required): User email address or UID whose access to revoke

**Examples:**

1. Revoke user access from a folder:
```bash
keeper-drive-revoke-access --folder xyz789abc123 --user colleague@example.com
```

2. Revoke access using user UID:
```bash
keeper-drive-revoke-access --folder xyz789abc123 --user user_uid_123
```

**Output:**
```
✓ Access revoked successfully
  Folder: xyz789abc123
  User: colleague@example.com
```

---

## Record Management

### keeper-drive-add-record

Create a new KeeperDrive record using the v3 API.

**Syntax:**
```bash
keeper-drive-add-record -t <title> [options] [field_specifications...]
```

**Parameters:**
- `-t, --title <title>` (required): Record title

**Options:**
- `-rt, --record-type <type>`: Record type (default: `login`)
- `-n, --notes <notes>`: Record notes
- `--folder <folder_uid>`: Folder UID, name, or path (omit for vault root)
- `-f, --force`: Ignore warnings
- `--syntax-help`: Display detailed field syntax help

**Field Specifications:**

Fields are specified using the format: `field_type=value`

Common field types for `login` records:
- `login`: Login/username
- `password`: Password
- `url`: URL
- `oneTimeCode`: TOTP secret for 2FA

**Examples:**

1. Create a basic login record:
```bash
keeper-drive-add-record -t "Gmail Account" -rt login \
  login=user@gmail.com \
  password=SecurePass123
```

2. Create a login with URL:
```bash
keeper-drive-add-record -t "Company Portal" -rt login \
  login=admin \
  password=Pass123! \
  url=https://portal.company.com
```

3. Create a record in a specific folder:
```bash
keeper-drive-add-record -t "Dev Server" -rt login \
  --folder xyz789abc123 \
  login=root \
  password=DevPass123 \
  url=ssh://dev.server.com
```

4. Create a record with notes:
```bash
keeper-drive-add-record -t "API Key" -rt login \
  -n "Production API key for main service" \
  login=api_user \
  password=api_key_12345
```

5. Field values with spaces:
```bash
keeper-drive-add-record -t "My Account" -rt login \
  "login=user name with spaces" \
  "password=pass word"
```

6. Get field syntax help:
```bash
keeper-drive-add-record --syntax-help
```

**Output:**
```
✓ Record 'Gmail Account' created successfully at vault root
  Record UID: rec123abc456
  Revision: 0
```

**Tips:**
- For record type information, use the `record-type-info` command
- Quotes are required if field values contain spaces
- Multiple URLs or custom fields can be specified by using field labels: `url.primary=...`, `url.backup=...`

---

### keeper-drive-update-record

Update an existing KeeperDrive record.

**Syntax:**
```bash
keeper-drive-update-record <record_uid> [options]
```

**Parameters:**
- `<record_uid>` (required): Record UID to update

**Options:**
- `--title <new_title>`: New title for the record
- `--type <record_type>`: New record type (e.g., `login`, `password`)
- `--login <login>`: New login/username
- `--password <password>`: New password
- `--url <url>`: New URL
- `--notes <notes>`: New notes

**Note:** At least one update option must be provided.

**Examples:**

1. Update record password:
```bash
keeper-drive-update-record rec123abc456 --password NewSecurePass456
```

2. Update title and login:
```bash
keeper-drive-update-record rec123abc456 \
  --title "Updated Account" \
  --login newuser@example.com
```

3. Update multiple fields:
```bash
keeper-drive-update-record rec123abc456 \
  --title "Production Server" \
  --login admin \
  --password NewPass789 \
  --url https://prod.server.com
```

4. Change record type:
```bash
keeper-drive-update-record rec123abc456 --type password
```

**Output:**
```
✓ Record 'rec123abc456' updated successfully
  Status: RS_SUCCESS
  Revision: 3
```

**Tips:**
- Record must exist in your vault before updating
- Run `sync-down` if you get "record not found" errors
- Updating a field replaces its value, not append to it

---

### keeper-drive-get-record-details

Get record metadata (title, color, version, revision) for specified records.

**Syntax:**
```bash
keeper-drive-get-record-details <record_uid> [<record_uid>...] [options]
```

**Parameters:**
- `<record_uid>` (required): One or more record UIDs to get details for

**Options:**
- `--format <format>`: Output format (default: `table`)
  - Choices: `table`, `json`

**Examples:**

1. Get details for a single record:
```bash
keeper-drive-get-record-details rec123abc456
```

2. Get details for multiple records:
```bash
keeper-drive-get-record-details rec123abc456 rec789def012 rec345ghi678
```

3. Get details in JSON format:
```bash
keeper-drive-get-record-details rec123abc456 --format json
```

**Output (table format):**
```
=== Record Details ===

Record UID: rec123abc456
  Title: Gmail Account
  Type: login
  Version: 3
  Revision: 5

Total records retrieved: 1
```

**Output (JSON format):**
```json
{
  "data": [
    {
      "record_uid": "rec123abc456",
      "title": "Gmail Account",
      "type": "login",
      "revision": 5,
      "version": 3
    }
  ],
  "forbidden_records": []
}
```

---

## Record Sharing

### keeper-drive-share-record

Share a record with a user using role-based permissions.

**Syntax:**
```bash
keeper-drive-share-record <record_uid> <recipient_email> <role_flag> [options]
```

**Parameters:**
- `<record_uid>` (required): Record UID to share
- `<recipient_email>` (required): Email address of recipient user

**Role Flags (required, mutually exclusive):**
- `--viewer`: Grant VIEWER role (can view record)
- `--contributor`: Grant CONTRIBUTOR role (can view and edit record)
- `--shared-manager`: Grant SHARED_MANAGER role (can manage sharing)
- `--content-manager`: Grant CONTENT_MANAGER role (can manage record content)
- `--manager`: Grant MANAGER role (full management permissions)

**Options:**
- `--expiration <timestamp>`: Expiration timestamp in milliseconds

**Examples:**

1. Share record with viewer access:
```bash
keeper-drive-share-record rec123abc456 colleague@example.com --viewer
```

2. Share record with edit permissions:
```bash
keeper-drive-share-record rec123abc456 teammate@example.com --contributor
```

3. Share record with manager access:
```bash
keeper-drive-share-record rec123abc456 manager@example.com --manager
```

4. Share record with expiration:
```bash
keeper-drive-share-record rec123abc456 temp@example.com --viewer \
  --expiration 1700000000000
```

**Output:**
```
✓ Record 'rec123abc456' shared with colleague@example.com
  Status: SUCCESS
  Role: VIEWER
```

**Access Roles Explained:**
- **VIEWER**: Can only view the record, no editing or sharing
- **CONTRIBUTOR**: Can view and edit record contents
- **SHARED_MANAGER**: Can manage who the record is shared with
- **CONTENT_MANAGER**: Can manage all aspects of record content
- **MANAGER**: Full control including sharing and deletion

---

### keeper-drive-update-record-share

Update sharing permissions for a record using role-based permissions.

**Syntax:**
```bash
keeper-drive-update-record-share <record_uid> <recipient_email> <role_flag> [options]
```

**Parameters:**
- `<record_uid>` (required): Record UID
- `<recipient_email>` (required): Email address of recipient user

**Role Flags (required, mutually exclusive):**
- `--viewer`: Update to VIEWER role (can view record)
- `--contributor`: Update to CONTRIBUTOR role (can view and edit record)
- `--shared-manager`: Update to SHARED_MANAGER role (can manage sharing)
- `--content-manager`: Update to CONTENT_MANAGER role (can manage record content)
- `--manager`: Update to MANAGER role (full management permissions)

**Options:**
- `--expiration <timestamp>`: Update expiration timestamp in milliseconds

**Examples:**

1. Update user role to contributor:
```bash
keeper-drive-update-record-share rec123abc456 colleague@example.com --contributor
```

2. Update user role to manager:
```bash
keeper-drive-update-record-share rec123abc456 colleague@example.com --manager
```

3. Update role with new expiration:
```bash
keeper-drive-update-record-share rec123abc456 colleague@example.com --viewer \
  --expiration 1700000000000
```

4. Downgrade access from manager to viewer:
```bash
keeper-drive-update-record-share rec123abc456 colleague@example.com --viewer
```

**Output:**
```
✓ Record 'rec123abc456' permissions updated for colleague@example.com
  Status: SUCCESS
  New Role: VIEWER
```

---

### keeper-drive-unshare-record

Revoke record sharing from a user.

**Syntax:**
```bash
keeper-drive-unshare-record <record_uid> <recipient_email>
```

**Parameters:**
- `<record_uid>` (required): Record UID
- `<recipient_email>` (required): Email address of user to unshare from

**Examples:**

1. Unshare record from a user:
```bash
keeper-drive-unshare-record rec123abc456 colleague@example.com
```

2. Revoke access completely:
```bash
keeper-drive-unshare-record rec123abc456 temp@example.com
```

**Output:**
```
✓ Record 'rec123abc456' unshared from colleague@example.com
  Status: SUCCESS
```

**Warning:** This completely removes the user's access to the record.

---

### keeper-drive-get-record-access

Get record access information showing who has access and their permissions.

**Syntax:**
```bash
keeper-drive-get-record-access <record_uid> [<record_uid>...] [options]
```

**Parameters:**
- `<record_uid>` (required): One or more record UIDs to get access information for

**Options:**
- `--format <format>`: Output format (default: `table`)
  - Choices: `table`, `json`

**Examples:**

1. Get access info for a single record:
```bash
keeper-drive-get-record-access rec123abc456
```

2. Get access info for multiple records:
```bash
keeper-drive-get-record-access rec123abc456 rec789def012
```

3. Get access info in JSON format:
```bash
keeper-drive-get-record-access rec123abc456 --format json
```

**Output (table format):**
```
=== Record Access Information ===

Record: rec123abc456
  Accessor: colleague@example.com
    Type: AT_USER
    Owner: False
    Can Edit: True
    Can View: True
    Can Share: False
    Can Delete: False

Total access entries retrieved: 1
```

**Output (JSON format):**
```json
{
  "record_accesses": [
    {
      "record_uid": "rec123abc456",
      "accessor_name": "colleague@example.com",
      "access_type": "AT_USER",
      "access_type_uid": "user_uid_123",
      "owner": false,
      "can_edit": true,
      "can_view": true,
      "can_share": false,
      "can_delete": false,
      "can_request_access": false,
      "can_approve_access": false
    }
  ],
  "forbidden_records": []
}
```

---

## Record Ownership

### keeper-drive-transfer-record

Transfer record ownership to another user.

**Syntax:**
```bash
keeper-drive-transfer-record <record_uid> <new_owner_email>
```

**Parameters:**
- `<record_uid>` (required): Record UID to transfer
- `<new_owner_email>` (required): Email address of the new owner

**Examples:**

1. Transfer record ownership:
```bash
keeper-drive-transfer-record rec123abc456 newowner@example.com
```

2. Transfer to another team member:
```bash
keeper-drive-transfer-record rec123abc456 manager@example.com
```

**Output:**
```
✓ Record 'rec123abc456' ownership transferred to newowner@example.com
  Status: success
  ⚠️  You will no longer have access to this record!
```

**Important Warnings:**
- ⚠️ **You will lose access to the record after transfer**
- The new owner will have complete control over the record
- The new owner must be a valid user in your enterprise
- This action cannot be easily reversed

**Use Cases:**
- Employee leaving the organization
- Reassigning records to new team members
- Consolidating record ownership

---

## Folder-Record Management

### keeper-drive-add-record-to-folder

Add an existing record to a KeeperDrive folder.

**Syntax:**
```bash
keeper-drive-add-record-to-folder --folder <folder_uid> --record <record_uid>
```

**Parameters:**
- `--folder <folder_uid>` (required): Folder UID, name, or path
- `--record <record_uid>` (required): Record UID to add to the folder

**Examples:**

1. Add record to a folder:
```bash
keeper-drive-add-record-to-folder \
  --folder xyz789abc123 \
  --record rec123abc456
```

2. Add record using folder name:
```bash
keeper-drive-add-record-to-folder \
  --folder "My Projects" \
  --record rec123abc456
```

**Output:**
```
✓ Record added to folder successfully
  Folder: xyz789abc123
  Record: rec123abc456
```

**Notes:**
- Record and folder must already exist
- Record can be in multiple folders simultaneously
- Record key is encrypted with the folder key for security

---

### keeper-drive-remove-record-from-folder

Remove a record from a KeeperDrive folder.

**Syntax:**
```bash
keeper-drive-remove-record-from-folder --folder <folder_uid> --record <record_uid>
```

**Parameters:**
- `--folder <folder_uid>` (required): Folder UID, name, or path
- `--record <record_uid>` (required): Record UID to remove from the folder

**Examples:**

1. Remove record from a folder:
```bash
keeper-drive-remove-record-from-folder \
  --folder xyz789abc123 \
  --record rec123abc456
```

2. Remove using folder name:
```bash
keeper-drive-remove-record-from-folder \
  --folder "Archive" \
  --record rec123abc456
```

**Output:**
```
✓ Record removed from folder successfully
  Folder: xyz789abc123
  Record: rec123abc456
```

**Notes:**
- This only removes the record from the folder, not from your vault
- The record will still exist and can be accessed from other locations
- Does not affect record sharing or permissions

---

### keeper-drive-move-record

Move a record between folders or to/from root.

**Syntax:**
```bash
keeper-drive-move-record <record_uid> [--from <source_folder>] [--to <dest_folder>]
```

**Parameters:**
- `<record_uid>` (required): Record UID to move

**Options:**
- `--from <source_folder>`: Source folder UID, name, or path (omit for root)
- `--to <dest_folder>`: Destination folder UID, name, or path (omit for root)

**Note:** At least one of `--from` or `--to` must be specified. Both source and destination cannot be root.

**Examples:**

1. Move record from one folder to another:
```bash
keeper-drive-move-record rec123abc456 \
  --from xyz789abc123 \
  --to def456ghi789
```

2. Move record from folder to root:
```bash
keeper-drive-move-record rec123abc456 --from xyz789abc123
```

3. Move record from root to a folder:
```bash
keeper-drive-move-record rec123abc456 --to xyz789abc123
```

4. Move using folder names:
```bash
keeper-drive-move-record rec123abc456 \
  --from "Old Projects" \
  --to "Current Projects"
```

**Output:**
```
✓ Record moved successfully
  Record: rec123abc456
  From: xyz789abc123
  To: def456ghi789
```

**Use Cases:**
- Reorganizing your vault structure
- Moving records to more appropriate folders
- Moving records out of shared folders
- Archiving old records

---

## Common Workflows

### Creating a Complete Folder Structure with Records

```bash
# 1. Create a main folder
keeper-drive-mkdir "Client Projects" --color blue

# 2. Create a record in the folder
keeper-drive-add-record -t "Client Portal Login" -rt login \
  --folder "Client Projects" \
  login=admin@client.com \
  password=SecurePass123 \
  url=https://portal.client.com

# 3. Share folder with team members
keeper-drive-grant-access \
  --folder "Client Projects" \
  --user colleague@company.com \
  --role contributor

# 4. List to verify
keeper-drive-list --folders --permissions
```

### Sharing Records with Specific Permissions

```bash
# 1. Share record with viewer access
keeper-drive-share-record rec123abc456 \
  viewer@company.com \
  --viewer

# 2. Share record with edit access for 30 days
keeper-drive-share-record rec789def012 \
  contractor@external.com \
  --contributor \
  --expire 30d

# 3. Check who has access
keeper-drive-get-record-access rec123abc456
```

### Reorganizing Vault Structure

```bash
# 1. Create new folder structure
keeper-drive-mkdir "Archive 2024" --color gray

# 2. Move old records to archive
keeper-drive-move-record rec123abc456 \
  --from "Active Projects" \
  --to "Archive 2024"

# 3. Update folder properties
keeper-drive-update-folder "Archive 2024" \
  --name "Archive 2024 (Completed)" \
  --color gray
```

### Transferring Ownership

```bash
# 1. Get record details
keeper-drive-get-record-details rec123abc456

# 2. Check current access
keeper-drive-get-record-access rec123abc456

# 3. Transfer ownership
keeper-drive-transfer-record rec123abc456 newowner@company.com

# Warning: You will lose access after this operation!
```

---

## Best Practices

### Folder Management
1. **Use Descriptive Names**: Give folders clear, descriptive names that indicate their purpose
2. **Color Code**: Use colors to visually organize related folders (e.g., red for sensitive, blue for projects)
3. **Inherit Permissions**: Use `--no-inherit` sparingly; inheriting permissions simplifies management
4. **Regular Updates**: Keep folder names and colors up to date as your organization evolves

### Record Security
1. **Minimum Access**: Grant the minimum permissions necessary (start with viewer, upgrade as needed)
2. **Time-Limited Access**: Use expiration times for temporary access needs
3. **Regular Audits**: Periodically review record access with `keeper-drive-get-record-access`
4. **Sync Regularly**: Run `sync-down` before and after major operations to ensure consistency

### Access Management
1. **Role-Based Access**: Use appropriate roles (viewer, contributor, manager) based on actual needs
2. **Document Sharing**: Keep track of who has access to sensitive records
3. **Revoke Promptly**: Remove access immediately when it's no longer needed
4. **Use Expiration**: Set expiration dates for contractor or temporary access

### Organization
1. **Logical Structure**: Create a folder hierarchy that matches your team's workflow
2. **Consistent Naming**: Use consistent naming conventions across folders and records
3. **Archive Old Content**: Move completed projects to archive folders instead of deleting
4. **Batch Operations**: For multiple similar operations, consider using batch commands

---

## Troubleshooting

### Common Issues

**"Folder not found" Error**
```bash
# Solution: Sync your vault first
sync-down

# Then retry the command
keeper-drive-update-folder xyz789abc123 --name "New Name"
```

**"Record key not found" Error**
```bash
# Solution: Sync your vault to refresh keys
sync-down

# If issue persists, verify the record UID is correct
keeper-drive-list --records
```

**"User not found in enterprise" Error**
```bash
# Solution: Verify the user email is correct and they are in your enterprise
# You may need to run enterprise-down to refresh enterprise data
enterprise-down

# Then retry the command
keeper-drive-grant-access --folder xyz789 --user correct@email.com --role viewer
```

**Permission Denied Errors**
- Ensure you have the necessary permissions to perform the operation
- For folder operations, you need manager access to the folder
- For record operations, you need owner or appropriate share permissions

---

## API Limits

Be aware of these API limits when using KeeperDrive commands:

- **Folder Creation**: Maximum 100 folders per request (batch commands only)
- **Record Creation**: Maximum 1000 records per request (batch commands only)
- **Folder Access Updates**: Maximum 500 access entries per request (batch commands only)
- **Folder Record Updates**: Maximum 500 records per request (batch commands only)

For operations exceeding these limits, split them into multiple command invocations.

---

## Quick Reference

### Folder Commands
| Command | Purpose |
|---------|---------|
| `keeper-drive-mkdir` | Create a folder |
| `keeper-drive-update-folder` | Update folder properties |
| `keeper-drive-list --folders` | List folders |

### Folder Access Commands
| Command | Purpose |
|---------|---------|
| `keeper-drive-grant-access` | Grant user access to folder |
| `keeper-drive-update-access` | Update user's folder access |
| `keeper-drive-revoke-access` | Revoke user's folder access |

### Record Commands
| Command | Purpose |
|---------|---------|
| `keeper-drive-add-record` | Create a record |
| `keeper-drive-update-record` | Update record fields |
| `keeper-drive-get-record-details` | Get record metadata |
| `keeper-drive-list --records` | List records |

### Record Sharing Commands
| Command | Purpose |
|---------|---------|
| `keeper-drive-share-record` | Share record with user |
| `keeper-drive-update-record-share` | Update sharing permissions |
| `keeper-drive-unshare-record` | Unshare record from user |
| `keeper-drive-get-record-access` | Get record access info |
| `keeper-drive-transfer-record` | Transfer record ownership |

### Folder-Record Management Commands
| Command | Purpose |
|---------|---------|
| `keeper-drive-add-record-to-folder` | Add record to folder |
| `keeper-drive-remove-record-from-folder` | Remove record from folder |
| `keeper-drive-move-record` | Move record between folders |

---

## See Also

- **Batch Commands Documentation**: For information on batch operations (commands ending with `-batch`)
- **Record Type Info**: Use `record-type-info` command to see available record types and their fields
- **General Commander Help**: Use `help` command for overview of all available commands
- **Sync Commands**: `sync-down` to synchronize your vault with the server

---

## Support

For additional help:
- Use `<command> --help` for command-specific help
- Run `help` for general Commander help
- Visit the Keeper Security documentation
- Contact Keeper Support for account-specific issues

---

*Document Version: 1.0*  
*Last Updated: November 2025*  
*Compatible with: Keeper Commander v3 API*

