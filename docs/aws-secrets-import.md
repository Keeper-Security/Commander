# `aws-secrets-import` — Import AWS Secrets Manager Secrets into Keeper

The `aws-secrets-import` command reads every secret from AWS Secrets Manager and creates a corresponding Keeper record in a specified shared folder. Each secret's name becomes the record title; the secret's value is parsed into named fields on the record.

- **Alias:** `asi`
- **Requires:** `boto3` — install with `pip install keeper-commander[aws]`

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

The command resolves AWS credentials in the following order:

1. **Explicit flags** — `--access-key` and `--secret-key` provided directly on the command line.
2. **boto3 credential chain** — if no explicit flags are given, the standard boto3 session is used, which checks (in order):
   - Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, etc.)
   - `~/.aws/credentials` and `~/.aws/config`
   - IAM role attached to the running EC2 instance or ECS task

In most production deployments you can omit the credential flags entirely and let the instance role or `~/.aws` configuration handle authentication.

---

## Basic Usage

```
aws-secrets-import <folder-uid> [options]
```

The only required argument is the **shared folder UID** — the unique identifier of the Keeper shared folder that will receive the imported records. Use `list-sf` inside Commander to find the UID for a folder:

```
My Vault> list-sf
```

---

## Arguments & Flags

### Positional argument

| Argument | Description |
|---|---|
| `folder` | **Required.** Shared folder UID to import secrets into. |

### Credential flags

| Flag | Description |
|---|---|
| `--access-key KEY` | AWS access key ID. Overrides the boto3 credential chain. |
| `--secret-key SECRET` | AWS secret access key. Required when `--access-key` is provided. |
| `--region REGION` | AWS region name (e.g. `us-east-1`). Uses the boto3 default if omitted. |

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

### Name filters

Name filters operate on the full secret name as stored in AWS.

```bash
# Exact name match
asi xAbCdEfGhIjK --name prod/database/primary

# All secrets under the prod/ path
asi xAbCdEfGhIjK --name-starts-with prod/

# Secrets whose name ends with /credentials
asi xAbCdEfGhIjK --name-ends-with /credentials

# Secrets whose name contains "rds"
asi xAbCdEfGhIjK --name-contains rds
```

Multiple name filters can be combined. Each one adds an additional requirement:

```bash
# Must start with "prod/" AND contain "database"
asi xAbCdEfGhIjK --name-starts-with prod/ --name-contains database
```

### Tag filter

The `--tags` flag accepts a comma-separated list of `KEY=VALUE` pairs. A secret is included only if it carries **all** of the specified tags with the exact values given.

```bash
# Single tag requirement
asi xAbCdEfGhIjK --tags Env=prod

# Multiple tag requirements (both must match)
asi xAbCdEfGhIjK --tags Env=prod,Team=payments
```

Tag keys and values are case-sensitive and must match the values stored in AWS exactly.

### Combining filters

All filter types can be used together in one command:

```bash
asi xAbCdEfGhIjK \
  --name-starts-with prod/ \
  --name-ends-with /creds \
  --tags Env=prod,Owner=platform
```

A secret is imported only if it satisfies **every** filter listed.

---

## Secret Value Formats

When a secret is retrieved from AWS Secrets Manager, its `SecretString` is parsed into a set of named field values using the following rules, applied in priority order:

### 1. JSON object

If the secret string begins with `{` and is valid JSON representing an object, each key/value pair in the object becomes a separate field on the Keeper record.

```json
{
  "username": "admin",
  "password": "s3cur3P@ss!",
  "host": "db.internal.example.com"
}
```

Results in three fields: `username`, `password`, and `host`.

### 2. KEY=VALUE lines (shell-style)

If the secret string is not JSON, the command attempts to parse it as newline-separated `KEY=VALUE` pairs (the same format used by `.env` files). Lines beginning with `#` and blank lines are ignored.

```
# Database credentials
username=admin
password=s3cur3P@ss!
host=db.internal.example.com
```

Results in three fields: `username`, `password`, and `host`.

### 3. Fallback — plain string

If the secret string cannot be parsed as JSON or as `KEY=VALUE` lines, the entire string is stored as a single field named `value`.

```
s3cur3P@ss!
```

Results in one field: `value = s3cur3P@ss!`.

---

## Keeper Record Structure

Each imported secret produces one **TypedRecord** in the target shared folder:

- **Title** — the original AWS secret name (e.g. `prod/database/primary`).
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

### Import all secrets using ambient AWS credentials

```bash
asi xAbCdEfGhIjK
```

Uses `~/.aws` credentials or the attached EC2/ECS instance role automatically.

### Specify credentials and region explicitly

```bash
asi xAbCdEfGhIjK \
  --access-key AKIAIOSFODNN7EXAMPLE \
  --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  --region us-west-2
```

### Preview what would be imported (dry run)

```bash
asi xAbCdEfGhIjK --dry-run
```

Prints the name of each secret that passes all filters without creating any records.

### Import only production secrets owned by the payments team

```bash
asi xAbCdEfGhIjK --name-starts-with prod/ --tags Team=payments
```

### Import a single known secret

```bash
asi xAbCdEfGhIjK --name prod/payments/stripe-api-key
```

### Import all RDS secrets in staging and store as `serverCredentials` records

```bash
asi xAbCdEfGhIjK \
  --name-contains rds \
  --tags Env=staging \
  --record-type serverCredentials
```

### Dry-run a complex filter before committing

```bash
asi xAbCdEfGhIjK \
  --name-starts-with prod/ \
  --name-ends-with /creds \
  --tags Env=prod,Owner=platform \
  --dry-run
```
