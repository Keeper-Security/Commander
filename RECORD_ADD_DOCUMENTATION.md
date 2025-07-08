# Record-Add Command Documentation

This document provides comprehensive examples for creating records using the `record-add` command in Keeper Commander. The command supports **dot notation** for field specification and **$JSON:** syntax for complex field types.

> **Note**: Keeper Commander supports line continuation using backslash (`\`) at the end of lines, allowing you to split long commands across multiple lines for better readability.
> 
> **Important**: Do not put spaces after the backslash (`\`) character. The line should end immediately with `\` with no trailing spaces, otherwise empty arguments will be created and cause parsing errors.

## Command Syntax

```bash
record-add --title "Record Title" --record-type "RECORD_TYPE" [OPTIONS] [FIELDS...]
```

### Key Arguments
- `--title` / `-t`: Record title (required)
- `--record-type` / `-rt`: Record type (required)
- `--notes` / `-n`: Record notes (optional)
- `--folder`: Folder path or UID to store the record (optional)
- `--force` / `-f`: Ignore warnings (optional)
- `--syntax-help`: Display field syntax help

### Field Syntax Overview

**Dot Notation Format:**
```
[FIELD_SET.][FIELD_TYPE][.FIELD_LABEL]=FIELD_VALUE
```

**Components:**
- `FIELD_SET`: Optional. `f` (fields) or `c` (custom)
- `FIELD_TYPE`: Field type (e.g., login, password, url, etc.)
- `FIELD_LABEL`: Optional field label
- `FIELD_VALUE`: The field value

**Special Value Syntax:**
- `$JSON:{"key": "value"}` - For complex object fields
- `$GEN` - Generate passwords, TOTP codes, or key pairs
- `file=@filename` - File attachments

## Record Types

Keeper Commander supports two types of records:

1. **Typed Records** - Structured records with predefined schemas (login, bankAccount, contact, etc.)
2. **Legacy Records** - General records (use `-rt legacy` or `-rt general`)

## Field Types and Examples

### Simple Field Types
- `login` - Username/login field
- `password` - Password field (masked)
- `url` - Website URL
- `email` - Email address
- `text` - Plain text
- `multiline` - Multi-line text
- `secret` - Masked text field
- `note` - Masked multiline text
- `oneTimeCode` - TOTP/2FA codes
- `date` - Unix epoch time or date strings

### Complex Field Types (use $JSON:)
- `phone` - Phone number with region/type
- `name` - Person's name (first, middle, last)
- `address` - Physical address
- `paymentCard` - Credit card details
- `bankAccount` - Bank account details
- `securityQuestion` - Security Q&A pairs
- `host` - Hostname/port combinations
- `keyPair` - SSH key pairs

## Quick Start Examples

### Basic Login Record
**Single-line version (safest for copy-paste):**
```bash
record-add -t "Gmail Account" -rt login login=john.doe@gmail.com password=SecurePass123 url=https://accounts.google.com
```

**Multi-line version (type manually, don't copy-paste):**
```bash
record-add -t "Gmail Account" -rt login \
  login=john.doe@gmail.com \
  password=SecurePass123 \
  url=https://accounts.google.com
```

### Basic Contact with Phone
```bash
record-add -t "John Smith" -rt contact \
  name='$JSON:{"first": "John", "middle": "Michael", "last": "Smith"}' \
  email=john.smith@email.com \
  phone.Mobile='$JSON:{"number": "(555) 555-1234", "type": "Mobile"}'
```

## Detailed Examples by Record Type

### 1. Login Records

```bash
# Basic login
record-add -t "Gmail Account" -rt login \
  login=john.doe@gmail.com \
  password=SecurePass123 \
  url=https://accounts.google.com

# Login with generated password
record-add -t "Work Account" -rt login \
  login=john.doe \
  password='$GEN:rand,16' \
  url=https://company.com

# Login with TOTP
record-add -t "Banking Login" -rt login \
  login=john.doe \
  password=MySecurePassword \
  url=https://mybank.com \
  oneTimeCode='$GEN'

# Login with security questions
record-add -t "Investment Account" -rt login \
  login=john.doe \
  password=InvestPass123 \
  url=https://investment.com \
  securityQuestion.Mother='$JSON:[{"question": "What is your mother'\''s maiden name?", "answer": "Smith"}]'

# Login with custom fields
record-add -t "Work VPN" -rt login \
  login=john.doe \
  password=VpnPass123 \
  url=https://vpn.company.com \
  c.text.Department="IT Security" \
  c.text.Employee_ID="EMP001"
```

### 2. Bank Account Records

```bash
# Basic bank account
record-add -t "Chase Checking" -rt bankAccount \
  bankAccount='$JSON:{"accountType": "Checking", "routingNumber": "021000021", "accountNumber": "123456789"}' \
  name='$JSON:{"first": "John", "last": "Doe"}' \
  login=john.doe \
  password=BankPass123

# Bank account with online banking
record-add -t "Wells Fargo Savings" -rt bankAccount \
  bankAccount='$JSON:{"accountType": "Savings", "routingNumber": "121042882", "accountNumber": "987654321"}' \
  name='$JSON:{"first": "Jane", "last": "Smith"}' \
  login=jane.smith \
  password=SavePass456 \
  url=https://wellsfargo.com \
  --notes "High yield savings account"
```

### 3. Credit Card Records

```bash
# Credit card
record-add -t "Chase Sapphire Preferred" -rt bankCard \
  paymentCard='$JSON:{"cardNumber": "4111111111111111", "cardExpirationDate": "12/2025", "cardSecurityCode": "123"}' \
  text.cardholderName="John Doe" \
  pinCode=1234 \
  login=john.doe \
  password=CardPass123

# Debit card
record-add -t "Bank of America Debit" -rt bankCard \
  paymentCard='$JSON:{"cardNumber": "5555555555554444", "cardExpirationDate": "08/2026", "cardSecurityCode": "456"}' \
  text.cardholderName="Jane Smith" \
  pinCode=5678
```

### 4. Contact Records

```bash
# Personal contact
record-add -t "John Smith" -rt contact \
  name='$JSON:{"first": "John", "middle": "Michael", "last": "Smith"}' \
  email=john.smith@email.com \
  phone.Mobile='$JSON:{"number": "(555) 555-1234", "type": "Mobile"}' \
  text.company="ABC Corporation"

# Business contact with multiple phone numbers
record-add -t "Dr. Sarah Johnson" -rt contact \
  name='$JSON:{"first": "Sarah", "last": "Johnson"}' \
  email=sarah.johnson@medical.com \
  phone.Work='$JSON:{"number": "(555) 987-6543", "type": "Work"}' \
  phone.Mobile='$JSON:{"number": "(555) 123-4567", "type": "Mobile"}' \
  text.company="Medical Associates" \
  c.text.Title="Chief Medical Officer"
```

### 5. Address Records

```bash
# Home address
record-add -t "Home Address" -rt address \
  address='$JSON:{"street1": "123 Main St", "street2": "Apt 4B", "city": "New York", "state": "NY", "zip": "10001", "country": "USA"}'

# Work address
record-add -t "Office Address" -rt address \
  address='$JSON:{"street1": "456 Business Ave", "city": "San Francisco", "state": "CA", "zip": "94105", "country": "USA"}' \
  --notes "Main office location"
```

### 6. Server Credentials

```bash
# Web server
record-add -t "Production Web Server" -rt serverCredentials \
  host='$JSON:{"hostName": "web.company.com", "port": "22"}' \
  login=admin \
  password='$GEN:rand,20' \
  c.text.Environment="Production" \
  c.text.Purpose="Web Server"

# Database server
record-add -t "MySQL Database" -rt databaseCredentials \
  host='$JSON:{"hostName": "db.company.com", "port": "3306"}' \
  login=dbadmin \
  password=DbSecure123 \
  text.database="production_db"
```

### 7. SSH Keys

```bash
# SSH key pair
record-add -t "Production SSH Key" -rt sshKeys \
  keyPair='$GEN:ed25519,enc' \
  host='$JSON:{"hostName": "prod.company.com", "port": "22"}' \
  login=deploy \
  c.text.Purpose="Production deployment"

# Existing SSH key
record-add -t "GitHub SSH Key" -rt sshKeys \
  keyPair='$JSON:{"privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...", "publicKey": "ssh-ed25519 AAAAC3..."}' \
  host='$JSON:{"hostName": "github.com", "port": "22"}' \
  login=git
```

### 8. Software Licenses

```bash
# Software license
record-add -t "Microsoft Office" -rt softwareLicense \
  licenseNumber="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" \
  c.text.Product_Version="Office 365" \
  c.text.Licensed_To="John Doe" \
  c.date.Purchase_Date="2023-01-15" \
  c.date.Expiration_Date="2024-01-15"
```

### 9. WiFi Credentials

```bash
# WiFi network
record-add -t "Home WiFi" -rt wifiCredentials \
  text.ssid="MyHomeNetwork" \
  password=WiFiPassword123 \
  c.text.Security_Type="WPA2" \
  c.text.Frequency="5GHz"
```

### 10. Secure Notes

```bash
# Basic secure note
record-add -t "Important Information" -rt encryptedNotes \
  note="This is confidential information that needs to be encrypted." \
  date="2024-01-15"

# Secure note with custom fields
record-add -t "Recovery Codes" -rt encryptedNotes \
  note="Backup codes for two-factor authentication" \
  c.text.Service="Google Authenticator" \
  c.multiline.Codes="123456\n789012\n345678"
```

### 11. File Attachments

```bash
# Record with file attachment
record-add -t "Important Document" -rt file \
  file='@/path/to/document.pdf' \
  --notes "Legal documents"

# Multiple file attachments
record-add -t "Project Files" -rt file \
  file='@/path/to/project.zip' \
  file='@/path/to/readme.txt' \
  c.text.Project_Name="Alpha Release"
```

## Advanced Features

### Password Generation

```bash
# Random password (default)
password='$GEN'
password='$GEN:rand,16'  # 16 characters

# Diceware password
password='$GEN:dice,5'   # 5 words

# Crypto password
password='$GEN:crypto'
```

### TOTP/2FA Generation

```bash
# Generate TOTP secret
oneTimeCode='$GEN'

# Existing TOTP URL
oneTimeCode='otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example'
```

### SSH Key Generation

```bash
# Generate RSA key pair
keyPair='$GEN:rsa'

# Generate EC key pair
keyPair='$GEN:ec'

# Generate Ed25519 key pair (recommended)
keyPair='$GEN:ed25519'

# Generate encrypted key pair
keyPair='$GEN:ed25519,enc'
```

### Custom Fields

```bash
# Custom text field
c.text.Department="Engineering"

# Custom multiline field
c.multiline.Notes="Line 1\nLine 2\nLine 3"

# Custom secret field (masked)
c.secret.API_Key="secret-api-key-here"

# Custom date field
c.date.Expiration="2024-12-31"
```

## Common Field Reference

### Date Formats
```bash
# Unix timestamp
date=1668639533

# ISO format
date="2022-11-16T10:58:53Z"

# Simple date
date="2022-11-16"
```

### Phone Number Format
```bash
phone.Work='$JSON:{"region": "US", "number": "(555) 555-1234", "ext": "123", "type": "Work"}'
phone.Mobile='$JSON:{"number": "(555) 555-1234", "type": "Mobile"}'
```

### Name Format
```bash
name='$JSON:{"first": "John", "middle": "Michael", "last": "Doe"}'
name='$JSON:{"first": "Jane", "last": "Smith"}'
```

### Address Format
```bash
address='$JSON:{"street1": "123 Main St", "street2": "Apt 4B", "city": "New York", "state": "NY", "zip": "10001", "country": "USA"}'
```

### Security Questions Format
```bash
securityQuestion.Mother='$JSON:[{"question": "What is your mother'\''s maiden name?", "answer": "Smith"}]'
securityQuestion.Pet='$JSON:[{"question": "What was your first pet'\''s name?", "answer": "Fluffy"}]'
```

## Self-Destructing Records (One-Time Shares)

The `--self-destruct` option creates temporary records that automatically delete themselves after being accessed. This is perfect for sharing sensitive information that should only be viewed once.

### How Self-Destruct Works

1. **Creates a temporary shareable URL** that expires after your specified time
2. **Record stays in your vault** until someone opens the share URL
3. **Auto-deletes from your vault** 5 minutes after the URL is first accessed
4. **Maximum duration** is 6 months

### Syntax

```bash
--self-destruct <NUMBER>[(m)inutes|(h)ours|(d)ays]
```

**Time Units:**
- `m` or `minutes` - Minutes (default if no unit specified)
- `h` or `hours` - Hours  
- `d` or `days` - Days

### Examples

**Share temporary password (expires in 1 hour):**
```bash
record-add -t "Temporary Server Access" -rt login \
  login=admin \
  password='$GEN:rand,16' \
  url=https://server.company.com \
  --self-destruct 1h \
  --notes "Emergency access for John Doe"
```

**One-time WiFi credentials (expires in 30 minutes):**
```bash
record-add -t "Guest WiFi Access" -rt wifiCredentials \
  text.ssid="Company-Guest" \
  password=TempPass123 \
  --self-destruct 30m \
  --notes "Visitor access for meeting"
```

**Temporary file share (expires in 24 hours):**
```bash
record-add -t "Confidential Document" -rt file \
  file='@/path/to/sensitive-doc.pdf' \
  --self-destruct 1d \
  --notes "Contract for review - auto-deletes after viewing"
```

**Emergency contact info (expires in 2 hours):**
```bash
record-add -t "Emergency Contact" -rt contact \
  name='$JSON:{"first": "Emergency", "last": "Contact"}' \
  phone.Mobile='$JSON:{"number": "(555) 911-0000", "type": "Emergency"}' \
  --self-destruct 2h
```

### Return Value

When using `--self-destruct`, the command returns a **shareable URL** instead of a record UID:

```bash
$ record-add -t "Temp Password" -rt login login=user password=pass123 --self-destruct 1h
https://keepersecurity.com/vault/share/AbCdEf123456...
```

### Important Notes

⚠️ **Security Considerations:**
- **URL is the key** - Anyone with the URL can access the record
- **No authentication required** - Share URLs bypass login requirements  
- **One-time access** - Record deletes 5 minutes after first view
- **Cannot be recovered** - Once deleted, the record is gone forever

⚠️ **Limitations:**
- **Maximum 6 months** expiration time
- **Cannot update** self-destructing records
- **No preview** - You can't see the record again after creation
- **Immediate sharing** - URL is active immediately upon creation

### Best Practices

1. **Copy the URL immediately** - You won't be able to retrieve it later
2. **Use short expiration times** for maximum security (minutes/hours vs days)
3. **Include context in notes** about why the record was created
4. **Share URL through secure channels** (encrypted messaging, in person)
5. **Generate strong passwords** using `$GEN` for temporary access
6. **Verify recipient received URL** before the expiration time

### Use Cases

- **Emergency access credentials** for system administrators
- **Temporary passwords** for contractors or consultants  
- **One-time document sharing** for sensitive files
- **Guest network credentials** for visitors
- **Secure information handoffs** between team members
- **Time-sensitive shared secrets** for automated systems

### Example Workflow

```bash
# 1. Create self-destructing record
URL=$(record-add -t "Emergency DB Access" -rt databaseCredentials \
  host='$JSON:{"hostName": "db.company.com", "port": "5432"}' \
  login=emergency_user \
  password='$GEN:rand,20' \
  text.database="production" \
  --self-destruct 4h \
  --notes "Emergency access for incident response - $(date)")

# 2. Share URL securely (example with secure messaging)
echo "Emergency database access: $URL" | secure-send user@company.com

# 3. Record will auto-delete 5 minutes after first access
```

## Tips and Best Practices

1. **Use single-line commands for copy-paste** to avoid trailing space issues
2. **Quote JSON values** to prevent shell interpretation
3. **Use $GEN for passwords** instead of hardcoding them
4. **Test with simple records first** before creating complex ones
5. **Use custom fields (c.) for non-standard data**
6. **Organize records in folders** using the `--folder` parameter
7. **Add meaningful notes** with `--notes` for context

## Troubleshooting

### Common Issues

**"Expected: <field>=<value>, got: ; Missing `=`"**
- Remove trailing spaces after backslashes in multi-line commands
- Use single-line format for copy-paste

**"Field type not supported"**
- Check available field types with `record-add --syntax-help`
- Use custom fields with `c.` prefix for non-standard fields

**JSON parsing errors**
- Ensure JSON is properly quoted
- Escape single quotes in JSON: `'\''`
- Use double quotes inside JSON objects

**File attachment errors**
- Use `@` prefix: `file=@/path/to/file.txt`
- Ensure file path is accessible
- Use absolute paths to avoid confusion

## Record-Update vs Record-Add

While `record-add` creates new records, `record-update` modifies existing records. Here's how they compare:

### Key Differences

| Feature | record-add | record-update |
|---------|------------|---------------|
| Purpose | Creates new records | Modifies existing records |
| Record identifier | Not required | **Required** (`-r` or `--record`) |
| Record type | Required (`-rt`) | Optional (can change type) |
| Field behavior | Sets all fields | Updates only specified fields |
| Notes behavior | Sets notes | Appends with `+` prefix, overwrites without |

### Record-Update Syntax

```bash
record-update --record "RECORD_TITLE_OR_UID" [OPTIONS] [FIELDS...]
```

**Key Arguments:**
- `--record` / `-r`: Record title or UID (required)
- `--title` / `-t`: Update record title
- `--record-type` / `-rt`: Change record type
- `--notes` / `-n`: Update notes (`+text` appends, `text` overwrites)
- `--force` / `-f`: Ignore warnings

### Examples

**Update password and URL:**
```bash
record-update -r "Gmail Account" \
  password='$GEN:rand,20' \
  url=https://accounts.google.com/new-login
```

**Add a phone number to existing contact:**
```bash
record-update -r "John Smith" \
  phone.Work='$JSON:{"number": "(555) 987-6543", "type": "Work"}'
```

**Append to notes (notice the + prefix):**
```bash
record-update -r "Server Credentials" \
  --notes "+Updated password on 2024-01-15"
```

**Update title and add custom field:**
```bash
record-update -r "Old Server Name" \
  --title "Production Web Server" \
  c.text.Environment="Production" \
  c.text.Last_Updated="2024-01-15"
```

**Change record type (converts structure):**
```bash
record-update -r "Simple Login" \
  --record-type contact \
  name='$JSON:{"first": "John", "last": "Doe"}' \
  email=john.doe@example.com
```

### When to Use Each Command

**Use `record-add` when:**
- Creating a completely new record
- You want to specify all fields from scratch
- Setting up initial record structure

**Use `record-update` when:**
- Modifying existing records
- Adding new fields to existing records
- Updating passwords or other credentials
- Appending information to notes
- Converting between record types

**Important Notes:**
- `record-update` only changes the fields you specify
- Existing fields not mentioned remain unchanged
- Use `field=` (empty value) to clear a field
- Notes with `+` prefix append, without `+` they replace

## Getting Help

```bash
# View all available record types
record-type-info

# View fields for a specific record type
record-type-info --list-record login

# View field information
record-type-info --list-field phone

# View field syntax help
record-add --syntax-help

# View record-update syntax help
record-update --help
``` 