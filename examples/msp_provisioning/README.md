# Python MC Provisioning Script Guide

## Overview

`provision_mc_template.py` is a Python automation script that provisions complete Managed Company (MC) instances from YAML templates. It automates the entire workflow:

1. Creates the Managed Company
2. Switches to MC context
3. Creates dedicated admin user
4. Creates folder structure (with nested folders)
5. Shares folders with MSP technicians
6. Switches back to MSP context

## Prerequisites

**Before you begin, you need:**

1. **Python 3.7 or higher**
   ```bash
   python3 --version
   ```

2. **Keeper Commander repository** (this script runs from the repo)
   ```bash
   # Clone the Commander repository if you haven't already
   git clone https://github.com/Keeper-Security/Commander.git
   cd Commander
   ```

3. **Python virtual environment** (optional but recommended)
   ```bash
   # From the Commander root directory
   python3 -m venv venv
   source venv/bin/activate  # On Mac/Linux
   # or
   venv\Scripts\activate  # On Windows
   ```

4. **Keeper Commander package**
   ```bash
   # Install Keeper Commander (includes all dependencies including PyYAML)
   pip3 install keepercommander
   ```

5. **MSP Administrator account** with permissions to create Managed Companies

## ⚠️ IMPORTANT: Email Domain Reservation

**Before running this script, you MUST reserve the admin user's email domain for the Managed Company.**

Keeper requires email domains to be reserved before you can auto-create user accounts without email verification. This is a security feature to prevent unauthorized account creation.

### How to Reserve a Domain

Contact Keeper support to reserve a domain for your MC. Learn more:
- 📚 [Email Auto-Provisioning Documentation](https://docs.keeper.io/enterprise-guide/user-and-team-provisioning/email-auto-provisioning)

### What Happens if You Don't Reserve the Domain?

The script will detect the error and prompt you:
```
============================================================
DOMAIN NOT RESERVED ERROR
============================================================
Failed to create admin user: user@domain.com
Reason: Creating user accounts without email verification is only permitted on reserved domains.

Continue provisioning without admin user? (y/n):
```

**Your options:**
- **Type 'y'** - Skip admin user creation and continue with MC and folder provisioning
  - ✅ MC will be created
  - ✅ Folders will be created
  - ✅ Folders will be shared with MSP users
  - ⚠️ No admin user created (you can add manually later)

- **Type 'n'** - Stop provisioning completely
  - Nothing will be created

### Before Running:

1. **Check your template** - Open your YAML file (e.g., `template_simple.yaml`)
2. **Find the admin_user email** - Look for `admin_user: email:`
3. **Verify the domain is reserved** - Make sure that domain is reserved for your MC
4. **Update if needed** - Change to a reserved domain if necessary
5. **Or plan to skip** - If domain isn't reserved, you can still provision and skip the admin user

## Quick Start

Once you have the prerequisites installed:

```bash
# 1. Navigate to the script directory
cd examples/msp_provisioning/

# 2. Edit a template file
vim template_simple.yaml
# (Update the MC name, admin email, and folder structure)

# 3. Test your configuration (dry-run mode)
python3 provision_mc_template.py template_simple.yaml --dry-run

# 4. Run for real
python3 provision_mc_template.py template_simple.yaml
```

## First-Time Setup

### Login and Save Credentials (Optional but Recommended)

To avoid entering credentials every time, create a Keeper config file:

```bash
# From the examples/msp_provisioning/ directory
keeper shell --config config.json
# (Login with your MSP admin credentials when prompted)
# (Type 'quit' to exit)
```

This creates a `config.json` file that stores your session. Now you can run:

```bash
python3 provision_mc_template.py template.yaml --config config.json
```

## Usage

### Basic Usage

```bash
python3 provision_mc_template.py template.yaml
```

### With Options

```bash
# Preview without making changes
python3 provision_mc_template.py template.yaml --dry-run

# Use specific config file
python3 provision_mc_template.py template.yaml --config /path/to/config.json

# Enable debug logging
python3 provision_mc_template.py template.yaml --debug
```

## Template Format

### Minimal Template

```yaml
mc:
  name: "Client Corp"
  plan: "businessPlus"
  seats: -1

admin_user:
  email: "client@yourcompany.io"

folders:
  - name: "Accounting"
    type: "shared"
```

### Complete Template

See `template_acme_corp.yaml` for a full example with:
- MC configuration (plan, seats, add-ons)
- Admin user setup
- Nested folder structures
- Folder colors
- Sharing configuration
- Permissions

### Template Structure

#### MC Configuration

```yaml
mc:
  name: "Company Name"          # Required
  plan: "businessPlus"          # Required: business, businessPlus, enterprise, enterprisePlus
  seats: -1                     # Optional: -1 for unlimited
  node: "Client Companies"      # Optional: node name or ID to organize this MC
  create_node: true              # Optional: auto-create node if it doesn't exist
  file_plan: "1tb"              # Optional: 100gb, 1tb, 10tb
  root_folder: "Acme Corp"      # Optional: MC root folder name (see below)
  folder_prefix: "Acme"         # Optional: prefix for subfolder names (see below)
  root_folder_color: "blue"     # Optional: color for root folder
  addons:                       # Optional
    - "compliance_report"
    - "secrets_manager"
```

**Node Organization:**

MSPs often organize their Managed Companies into nodes for better structure:

```
Enterprise Root
├── SMB Clients
│   ├── Client A MC
│   └── Client B MC
├── Enterprise Clients
│   ├── Client C MC
│   └── Client D MC
└── Trial Clients
    └── Test MC
```

**How to use nodes:**
- `node: "Client Companies"` - Specify the node name where the MC should be created
- `create_node: true` - Automatically create the node if it doesn't exist
- If the node already exists, it will be reused (no duplicate nodes created)
- If `create_node` is false or omitted, the node must already exist

**Internal MC Nodes:**

Large clients often need internal organizational structure within their MC. You can create nodes inside the MC for departments, locations, or business units:

```yaml
mc:
  name: "Acme Corporation"
  node: "Enterprise Clients"    # MSP-side organization
  create_node: true

  internal_nodes:                # MC-side organization
    - "Engineering"
    - "Sales"
    - "Operations"
```

This creates the following structure:

**MSP Enterprise (MSP side):**
```
MSP Root
└── Enterprise Clients
    └── Acme Corporation MC
```

**Acme Corporation MC (MC side):**
```
Acme Root
├── Engineering (node)
├── Sales (node)
└── Operations (node)
```

**Use cases:**
- Multi-department companies (Engineering, Sales, HR)
- Multi-location businesses (NYC Office, LA Office, Austin Office)
- Subsidiaries (Subsidiary A, Subsidiary B)

Users and folders can then be organized under these internal nodes using the `admin_user.node` parameter.

**Root Folder Feature:**

The `root_folder` setting creates a single MC root folder containing all subfolders, helping MSP technicians organize client folders in their vault:

- **Default**: MC name (e.g., "Acme Corporation" → creates "Acme Corporation/" folder)
- **Custom**: Set to any identifier (e.g., `root_folder: "Acme Corp"`)
- **Disable**: Set to `""` or `false` to create folders directly in vault root

**Why use a root folder?**

Without a root folder, shared folders clutter the MSP tech's vault:
```
MSP Tech's Vault:
├── Network          (Which client?)
├── Accounting       (Which client?)
├── HR               (Which client?)
├── Network          (Duplicate - confusing!)
```

With root folder (automatic):
```
MSP Tech's Vault:
├── Acme Corporation/
│   ├── Network
│   ├── Accounting
│   └── HR
├── Beta Industries/
│   ├── Network
│   ├── IT Systems
│   └── Finance
```

**Benefits:**
- Clean organization - all MC folders grouped under one root
- Easy identification - root folder name identifies the client
- Nested structure - subfolders remain cleanly nested

**Important Note:**
- The root folder is created as a **regular** folder (not shared)
- This is required because Keeper does not allow shared folders to be nested inside other shared folders
- Individual subfolders inside the root can be shared with MSP users using the `share_with` parameter

**Folder Prefix Feature:**

The `folder_prefix` setting adds prefixes to subfolder names so MSP techs can identify which client a folder belongs to when folders are individually shared:

- **Default**: First word of MC name (e.g., "Acme Corporation" → "Acme-")
- **Custom**: Set to any short identifier (e.g., `folder_prefix: "ACME"`)
- **Disable**: Set to `""` or `false` to skip prefixing

**Why use both root folder AND folder prefix?**

Keeper's folder sharing limitations require both approaches:
- **Root folders** organize inside the MC vault
- **Folder prefixes** identify client when individual folders are shared

**The Problem:** Keeper cannot share nested folder structures. When you share "Acme Corporation/Network" with an MSP tech, it appears in their vault as just "Network" (without the parent path). If they support multiple clients, they'll have confusion:

```
MSP Tech's Vault (without prefix):
├── Network          (Which client?)
├── Accounting       (Which client?)
├── Network          (Another client - duplicate name!)
```

**The Solution:** Use both root folder (for MC organization) AND prefix (for MSP tech identification):

**Inside MC vault:**
```
Acme Corporation/
├── Acme-Network
├── Acme-Accounting
└── Acme-HR
```

**When shared with MSP tech:**
```
MSP Tech's Vault:
├── Acme-Network     (Clearly Acme!)
├── Acme-Accounting  (Clearly Acme!)
├── Beta-Network     (Different client!)
```

**Configuration:**

```yaml
mc:
  root_folder: "Acme Corporation"  # Organizes folders inside MC
  folder_prefix: "Acme"            # Identifies client when folders are shared
```

**Benefits:**
- Clean organization inside MC vault (root folder groups everything)
- Clear identification when shared with MSP (prefix shows which client)
- Best of both worlds for MSP workflows

**Available Plans:**
- `business`
- `businessPlus`
- `enterprise`
- `enterprisePlus`

**Available Add-ons:**
- `enterprise_breach_watch`
- `compliance_report`
- `enterprise_audit_and_reporting`
- `msp_service_and_support`
- `secrets_manager`
- `connection_manager:N` (where N is number of seats)
- `chat`

#### Admin User Configuration

```yaml
admin_user:
  email: "user@company.io"     # Required
  name: "Display Name"         # Optional: defaults to email
  node: "Root"                 # Optional: defaults to "Root"
```

#### Folder Configuration

```yaml
folders:
  - name: "Folder Name"        # Required
    type: "shared"             # Optional: "shared" or "user", defaults to "shared"
    color: "blue"              # Optional: none, red, green, blue, orange, yellow, gray

    # Optional: Default permissions for folder
    permissions:
      manage_users: false
      manage_records: true
      can_share: true
      can_edit: true

    # Optional: Share with users
    share_with:
      - email: "tech@msp.com"
        manage_records: true
        manage_users: false

    # Optional: Nested subfolders
    subfolders:
      - name: "Subfolder 1"
        type: "shared"
      - name: "Subfolder 2"
        type: "shared"
```

**Folder Types:**
- `shared` - Shared folder (can be shared with users/teams)
- `user` - User folder (personal to a user)

**Folder Colors:**
- `none`, `red`, `green`, `blue`, `orange`, `yellow`, `gray`

**Permissions:**
- `manage_users` - Can add/remove users from folder
- `manage_records` - Can add/edit/delete records
- `can_share` - Can share records with others
- `can_edit` - Can edit records

## Examples

### Example 1: Simple Setup

```yaml
mc:
  name: "Quick Client"
  plan: "businessPlus"
  seats: -1

admin_user:
  email: "client@msp.com"

folders:
  - name: "Passwords"
    type: "shared"
    share_with:
      - email: "admin@msp.com"
        manage_records: true
```

Run:
```bash
python3 provision_mc_template.py template_simple.yaml
```

### Example 2: Complex Structure with Nesting

```yaml
mc:
  name: "Enterprise Client"
  plan: "enterprise"
  seats: 50
  addons:
    - "compliance_report"
    - "secrets_manager"

admin_user:
  email: "enterprise@msp.com"
  name: "Enterprise Admin"

folders:
  - name: "IT Infrastructure"
    type: "shared"
    color: "blue"
    share_with:
      - email: "it-admin@msp.com"
        manage_records: true
        manage_users: true
    subfolders:
      - name: "Network"
        type: "shared"
        subfolders:
          - name: "Routers"
          - name: "Switches"
      - name: "Servers"
        type: "shared"
        subfolders:
          - name: "Production"
          - name: "Development"
```

### Example 3: Multiple Teams

```yaml
folders:
  - name: "Accounting"
    type: "shared"
    color: "green"
    share_with:
      - email: "accounting-team@msp.com"
        manage_records: true

  - name: "HR"
    type: "shared"
    color: "blue"
    share_with:
      - email: "hr-team@msp.com"
        manage_records: true

  - name: "IT"
    type: "shared"
    color: "orange"
    share_with:
      - email: "it-team@msp.com"
        manage_records: true
      - email: "admin@msp.com"
        manage_records: true
        manage_users: true
```

## Dry Run Mode

Always test with `--dry-run` first:

```bash
python3 provision_mc_template.py template.yaml --dry-run
```

**Note:** Dry-run mode still requires you to login with MSP administrator credentials to validate permissions, but it will not create any resources.

This will:
- ✅ Validate the template
- ✅ Verify MSP administrator permissions
- ✅ Show what would be created
- ✅ Check for errors
- ❌ Not make any actual changes

Output example:
```
[DRY RUN] Creating MC: Acme Corporation
[DRY RUN] Switching to MC: Acme Corporation
[DRY RUN] Creating admin user: acme@msp.com
[DRY RUN] Creating folder: Accounting Software
  [DRY RUN] Would share with: alice@msp.com
[DRY RUN] Creating folder: Accounting Software/QuickBooks
```

## Output

The script provides detailed output:

```
============================================================
MC Provisioning Started
============================================================
Loading template from template_acme_corp.yaml
Creating MC: Acme Corporation
  Plan: businessPlus, Seats: -1
✓ MC created with ID: 12345
Switching to MC: Acme Corporation
✓ Switched to MC context
Creating admin user: acme@compuverse.io
✓ Admin user created: acme@compuverse.io

Creating folder structure...
Creating folder: Accounting Software
  ✓ Created: Accounting Software (UID: ABC123)
  Sharing Accounting Software with 1 user(s)
    → alice@msp.com (records: True, users: False)
      ✓ Shared with alice@msp.com
Creating folder: Accounting Software/QuickBooks
  ✓ Created: Accounting Software/QuickBooks (UID: DEF456)
...
Switching back to MSP
✓ Switched back to MSP

============================================================
MC Provisioning Complete!
============================================================
MC Name: Acme Corporation
MC ID: 12345
Admin User: acme@compuverse.io
Folders Created: 15
============================================================
```

## Troubleshooting

### "Not an MSP administrator"
**Problem:** You're not logged in as an MSP admin
**Solution:** Login with MSP super admin credentials

### "Node not found"
**Problem:** The specified node doesn't exist
**Solution:** Change `node: "Root"` or check node name with `enterprise-info --nodes`

### "Failed to share with user"
**Problem:** User doesn't exist or sharing failed
**Solution:**
- Verify the email address
- Ensure the user exists in Keeper
- Check permissions

### "Folder not found after creation"
**Problem:** Folder was created but UID lookup failed
**Solution:**
- This is usually a timing issue
- The folder was likely created successfully
- Check with `keeper tree` after completion

### Template validation errors
**Problem:** YAML syntax error or missing required fields
**Solution:**
- Validate YAML syntax with a YAML validator
- Check that `mc.name` and `mc.plan` are present
- Use `--debug` for detailed error messages

## Advanced Usage

### Using with CI/CD

```bash
#!/bin/bash
# Automated client provisioning script

CLIENT_NAME="$1"
CLIENT_EMAIL="$2"

cat > /tmp/client_template.yaml <<EOF
mc:
  name: "${CLIENT_NAME}"
  plan: "businessPlus"
  seats: -1

admin_user:
  email: "${CLIENT_EMAIL}"

folders:
  - name: "Standard Folder 1"
    type: "shared"
  - name: "Standard Folder 2"
    type: "shared"
EOF

python3 provision_mc_template.py /tmp/client_template.yaml --config /etc/keeper/config.json
```

### Batch Provisioning

```bash
# Provision multiple clients
for template in templates/*.yaml; do
    echo "Provisioning: $template"
    python3 provision_mc_template.py "$template"
    sleep 5  # Rate limiting
done
```

## Comparison to Batch Scripts

| Feature | Batch Scripts | Python Script |
|---------|--------------|---------------|
| Setup complexity | Low | Medium |
| Template reuse | Manual editing | YAML templates |
| Nested folders | Tedious | Easy |
| UID tracking | Manual | Automatic |
| Error handling | None | Built-in |
| Dry run | No | Yes |
| Validation | No | Yes |
| Best for | Quick one-offs | Repeated use, complex structures |

## Next Steps

1. **Create your template** - Use `template_simple.yaml` as a starting point
2. **Test with dry-run** - `python3 provision_mc_template.py template.yaml --dry-run`
3. **Provision for real** - `python3 provision_mc_template.py template.yaml`
4. **Verify** - Login to Keeper and check the MC was created correctly

## Support

For issues or questions:
- Check the troubleshooting section above
- Review the example templates
- Use `--debug` for detailed error messages
- See `MSP_CLIENT_SETUP_GUIDE.md` for manual workflow details