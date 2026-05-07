# `azure-secrets-import` — Import Azure Key Vault Secrets into Keeper

The `azure-secrets-import` command reads every enabled secret from an Azure Key Vault and creates a corresponding Keeper record in a specified shared folder. Each secret's name becomes the record title; the secret's value is parsed into named fields on the record.

- **Alias:** `azsi`
- **Requires:** `azure-keyvault-secrets` and `azure-identity` — install with `pip install keeper-commander[azure]`

---

## Table of Contents

1. [Authentication](#authentication)
2. [Basic Usage](#basic-usage)
3. [Arguments & Flags](#arguments--flags)
4. [Filtering Secrets](#filtering-secrets)
5. [Secret Value Formats](#secret-value-formats)
6. [Keeper Record Structure](#keeper-record-structure)
7. [Examples](#examples)

---

## Authentication

The command resolves Azure credentials in the following order:

1. **Service-principal flags** — if `--tenant-id`, `--client-id`, and `--client-secret` are all provided, a `ClientSecretCredential` is used for authentication. All three flags must be supplied together; providing only some of them is an error.
2. **`DefaultAzureCredential`** — if no explicit flags are given, the Azure SDK's `DefaultAzureCredential` chain is used, which checks (in order):
   - Environment variables (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, etc.)
   - Workload Identity (Kubernetes)
   - Managed Identity attached to the running Azure VM, App Service, or Container
   - Azure CLI (`az login`)
   - Azure PowerShell
   - Azure Developer CLI

In most production deployments you can omit the credential flags entirely and rely on Managed Identity or the Azure CLI.

---

## Basic Usage

```
azure-secrets-import <vault-name> <folder-uid> [options]
```

Two positional arguments are required:

- **`vault-name`** — the short name of the Azure Key Vault (e.g. `my-vault`). The command constructs the full vault URL as `https://<vault-name>.vault.azure.net/` automatically.
- **`folder-uid`** — the unique identifier of the Keeper shared folder that will receive the imported records. Use `list-sf` inside Commander to find this value:

```
My Vault> list-sf
```

---

## Arguments & Flags

### Positional arguments

| Argument | Description |
|---|---|
| `vault_name` | **Required.** Short name of the Azure Key Vault (e.g. `my-vault`). |
| `folder` | **Required.** Shared folder UID to import secrets into. |

### Credential flags

| Flag | Description |
|---|---|
| `--tenant-id ID` | Azure AD tenant ID. Required together with `--client-id` and `--client-secret`. |
| `--client-id ID` | Azure AD application (client) ID. Required together with `--tenant-id` and `--client-secret`. |
| `--client-secret SECRET` | Azure AD client secret. Required together with `--tenant-id` and `--client-id`. |

All three credential flags must be provided together for service-principal authentication. Omit all three to use `DefaultAzureCredential`.

### Behaviour flags

| Flag | Description |
|---|---|
| `--record-type TYPE` | Keeper record type for imported records. Defaults to `login`. |
| `--dry-run` | List secrets that would be imported without creating any records. |

### Filter flags

All filter flags are optional and combine with AND logic — a secret must satisfy every provided filter to be imported.

| Flag | Description |
|---|---|
| `--name NAME` | Import only the secret with this exact name. |
| `--name-starts-with PREFIX` | Import only secrets whose name starts with `PREFIX`. |
| `--name-ends-with SUFFIX` | Import only secrets whose name ends with `SUFFIX`. |
| `--name-contains SUBSTRING` | Import only secrets whose name contains `SUBSTRING`. |
| `--tags KEY=VALUE[,KEY=VALUE,...]` | Import only secrets tagged with **all** specified key/value pairs. |

---

## Filtering Secrets

Filters let you import a targeted subset of secrets without touching the rest. Every filter you specify must match for a secret to be imported.

Disabled secrets are always skipped regardless of any filter settings.

### Name filters

Name filters operate on the secret name as stored in Azure Key Vault.

```bash
# Exact name match
azsi my-vault xAbCdEfGhIjK --name database-primary-password

# All secrets whose name starts with "prod-"
azsi my-vault xAbCdEfGhIjK --name-starts-with prod-

# Secrets whose name ends with "-creds"
azsi my-vault xAbCdEfGhIjK --name-ends-with -creds

# Secrets whose name contains "postgres"
azsi my-vault xAbCdEfGhIjK --name-contains postgres
```

Multiple name filters can be combined. Each one adds an additional requirement:

```bash
# Must start with "prod-" AND contain "database"
azsi my-vault xAbCdEfGhIjK --name-starts-with prod- --name-contains database
```

### Tag filter

Azure Key Vault secrets support arbitrary key/value tags. The `--tags` flag accepts a comma-separated list of `KEY=VALUE` pairs. A secret is included only if it carries **all** of the specified tags with the exact values given.

```bash
# Single tag requirement
azsi my-vault xAbCdEfGhIjK --tags Env=prod

# Multiple tag requirements (both must match)
azsi my-vault xAbCdEfGhIjK --tags Env=prod,Team=payments
```

Tag keys and values are case-sensitive and must match the values stored in Azure exactly.

### Combining filters

All filter types can be used together in one command:

```bash
azsi my-vault xAbCdEfGhIjK \
  --name-starts-with prod- \
  --name-ends-with -creds \
  --tags Env=prod,Owner=platform
```

A secret is imported only if it satisfies **every** filter listed.

---

## Secret Value Formats

When a secret is retrieved from Azure Key Vault, its value is parsed into a set of named field values using the following rules, applied in priority order:

### 1. JSON object

If the secret value begins with `{` and is valid JSON representing an object, each key/value pair in the object becomes a separate field on the Keeper record.

```json
{
  "username": "admin",
  "password": "s3cur3P@ss!",
  "host": "db.internal.example.com"
}
```

Results in three fields: `username`, `password`, and `host`.

### 2. KEY=VALUE lines (shell-style)

If the secret value is not JSON, the command attempts to parse it as newline-separated `KEY=VALUE` pairs (the same format used by `.env` files). Lines beginning with `#` and blank lines are ignored.

```
# Database credentials
username=admin
password=s3cur3P@ss!
host=db.internal.example.com
```

Results in three fields: `username`, `password`, and `host`.

### 3. Fallback — plain string

If the secret value cannot be parsed as JSON or as `KEY=VALUE` lines, the entire string is stored as a single field named `value`.

```
s3cur3P@ss!
```

Results in one field: `value = s3cur3P@ss!`.

---

## Keeper Record Structure

Each imported secret produces one **TypedRecord** in the target shared folder:

- **Title** — the original Azure Key Vault secret name (e.g. `prod-database-primary`).
- **Record type** — controlled by `--record-type` (default: `login`).

### Field placement

Parsed key/value pairs from the secret are mapped to Keeper field types before being placed on the record:

| Parsed key (case-insensitive) | Keeper field type | Placement |
|---|---|---|
| `username`, `user`, `login` | `login` | Typed fields |
| `password`, `pass`, `secret`, `secret_value` | `password` | Typed fields |
| `url`, `endpoint`, `host` | `url` | Typed fields |
| anything else | `text` | Custom fields |

Fields whose type matches a known Keeper typed field (`login`, `password`, `url`, `email`, `text`, `note`) are placed in the record's **typed fields** list. All other parsed keys are stored as **custom fields** with type `text`.

---

## Examples

### Import all secrets using DefaultAzureCredential

```bash
azsi my-vault xAbCdEfGhIjK
```

Uses Managed Identity, Azure CLI login, or environment variables automatically.

### Authenticate with a service principal

```bash
azsi my-vault xAbCdEfGhIjK \
  --tenant-id 00000000-0000-0000-0000-000000000000 \
  --client-id 11111111-1111-1111-1111-111111111111 \
  --client-secret "MyClientSecretValue"
```

### Preview what would be imported (dry run)

```bash
azsi my-vault xAbCdEfGhIjK --dry-run
```

Prints the name of each secret that passes all filters without creating any records.

### Import only production secrets owned by the payments team

```bash
azsi my-vault xAbCdEfGhIjK --name-starts-with prod- --tags Team=payments
```

### Import a single known secret

```bash
azsi my-vault xAbCdEfGhIjK --name prod-stripe-api-key
```

### Import all database secrets in staging stored as `serverCredentials` records

```bash
azsi my-vault xAbCdEfGhIjK \
  --name-contains database \
  --tags Env=staging \
  --record-type serverCredentials
```

### Dry-run a complex filter before committing

```bash
azsi my-vault xAbCdEfGhIjK \
  --name-starts-with prod- \
  --name-ends-with -creds \
  --tags Env=prod,Owner=platform \
  --dry-run
```

### Import from a vault in a different tenant using service-principal credentials

```bash
azsi partner-vault xAbCdEfGhIjK \
  --tenant-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
  --client-id ffffffff-0000-1111-2222-333333333333 \
  --client-secret "PartnerAppSecret" \
  --tags Shared=true
```
