# `gcp-secrets-import` — Import GCP Secret Manager Secrets into Keeper

The `gcp-secrets-import` command reads every accessible secret from Google Cloud Secret Manager and creates a corresponding Keeper record in a specified shared folder. Each secret's name becomes the record title; the secret's value is parsed into named fields on the record.

- **Alias:** `gcsi`
- **Requires:** `google-cloud-secret-manager` — install with `pip install keeper-commander[gcp]`

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

The command resolves GCP credentials in the following order:

1. **Service account key file** — if `--service-account-file` is provided, the specified JSON key file is loaded and used for all API calls.
2. **Application Default Credentials (ADC)** — if no key file is provided, the GCP SDK's ADC chain is used, which checks (in order):
   - The `GOOGLE_APPLICATION_CREDENTIALS` environment variable (path to a service account key file)
   - User credentials set via `gcloud auth application-default login`
   - The service account attached to the running Compute Engine instance, Cloud Run service, GKE workload, or other GCP-hosted environment

In most production deployments you can omit `--service-account-file` and rely on Workload Identity or the attached service account.

---

## Basic Usage

```
gcp-secrets-import <folder-uid> --project-id <project> [options]
```

The positional `folder-uid` and the `--project-id` flag are both required:

- **`folder-uid`** — the unique identifier of the Keeper shared folder that will receive the imported records. Use `list-sf` inside Commander to find this value:

```
My Vault> list-sf
```

- **`--project-id`** — the GCP project ID (not the project number) that owns the secrets, e.g. `my-gcp-project`.

---

## Arguments & Flags

### Positional argument

| Argument | Description |
|---|---|
| `folder` | **Required.** Shared folder UID to import secrets into. |

### Credential flags

| Flag | Description |
|---|---|
| `--project-id ID` | **Required.** GCP project ID that owns the secrets (e.g. `my-gcp-project`). |
| `--service-account-file PATH` | Path to a GCP service account JSON key file. Uses Application Default Credentials when omitted. |

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
| `--tags KEY=VALUE[,KEY=VALUE,...]` | Import only secrets whose GCP labels match **all** specified key/value pairs. |

> **Note on GCP labels:** GCP Secret Manager uses the term *labels* rather than *tags*. The `--tags` flag maps directly to GCP labels — use it the same way you would for AWS or Azure.

---

## Filtering Secrets

Filters let you import a targeted subset of secrets without touching the rest. Every filter you specify must match for a secret to be imported.

Secrets whose `latest` version is disabled, destroyed, or inaccessible due to permissions are always skipped with a warning regardless of any filter settings.

### Name filters

Name filters operate on the short secret name (the last segment of the full GCP resource name `projects/{project}/secrets/{secret-id}`).

```bash
# Exact name match
gcsi xAbCdEfGhIjK --project-id my-project --name database-primary-password

# All secrets whose name starts with "prod-"
gcsi xAbCdEfGhIjK --project-id my-project --name-starts-with prod-

# Secrets whose name ends with "-creds"
gcsi xAbCdEfGhIjK --project-id my-project --name-ends-with -creds

# Secrets whose name contains "postgres"
gcsi xAbCdEfGhIjK --project-id my-project --name-contains postgres
```

Multiple name filters can be combined. Each one adds an additional requirement:

```bash
# Must start with "prod-" AND contain "database"
gcsi xAbCdEfGhIjK --project-id my-project \
  --name-starts-with prod- --name-contains database
```

### Label filter (`--tags`)

GCP Secret Manager secrets support arbitrary key/value *labels*. The `--tags` flag accepts a comma-separated list of `KEY=VALUE` pairs. A secret is included only if it carries **all** of the specified labels with the exact values given.

```bash
# Single label requirement
gcsi xAbCdEfGhIjK --project-id my-project --tags env=prod

# Multiple label requirements (both must match)
gcsi xAbCdEfGhIjK --project-id my-project --tags env=prod,team=payments
```

> GCP label keys and values are lowercase by convention and are case-sensitive. Ensure the values you provide match the casing stored in GCP.

### Combining filters

All filter types can be used together in one command:

```bash
gcsi xAbCdEfGhIjK --project-id my-project \
  --name-starts-with prod- \
  --name-ends-with -creds \
  --tags env=prod,owner=platform
```

A secret is imported only if it satisfies **every** filter listed.

---

## Secret Value Formats

When a secret is retrieved from GCP Secret Manager, the payload of the `latest` version is decoded as UTF-8 and then parsed into a set of named field values using the following rules, applied in priority order:

### 1. JSON object

If the secret payload begins with `{` and is valid JSON representing an object, each key/value pair in the object becomes a separate field on the Keeper record.

```json
{
  "username": "admin",
  "password": "s3cur3P@ss!",
  "host": "db.internal.example.com"
}
```

Results in three fields: `username`, `password`, and `host`.

### 2. KEY=VALUE lines (shell-style)

If the payload is not JSON, the command attempts to parse it as newline-separated `KEY=VALUE` pairs (the same format used by `.env` files). Lines beginning with `#` and blank lines are ignored.

```
# Database credentials
username=admin
password=s3cur3P@ss!
host=db.internal.example.com
```

Results in three fields: `username`, `password`, and `host`.

### 3. Fallback — plain string

If the payload cannot be parsed as JSON or as `KEY=VALUE` lines, the entire string is stored as a single field named `value`.

```
s3cur3P@ss!
```

Results in one field: `value = s3cur3P@ss!`.

---

## Keeper Record Structure

Each imported secret produces one **TypedRecord** in the target shared folder:

- **Title** — the short GCP secret name (e.g. `prod-database-primary`), not the full resource path.
- **Record type** — controlled by `--record-type` (default: `login`).

### Field placement

Parsed key/value pairs from the secret are mapped to Keeper field types before being placed on the record:

| Parsed key (case-insensitive) | Keeper field type | Placement |
|---|---|---|
| `username`, `user`, `login` | `login` | Typed fields |
| `password`, `pass`, `secret`, `secret_value` | `password` | Typed fields |
| `url`, `endpoint`, `host` | `url` | Typed fields |
| `email`, `mail` | `email` | Typed fields |
| `note`, `notes` | — | Record Notes section |
| anything else | `text` | Typed fields |

The `note` and `notes` keys are written to the record's **Notes** field rather than appearing as a typed or custom field. All other keys not listed above are stored as `text` typed fields. If the same semantic type (e.g. `login`, `password`, `url`, `email`) appears more than once, the first occurrence takes the typed field slot and subsequent ones are stored as **custom fields**.

---

## Examples

### Import all secrets using Application Default Credentials

```bash
gcsi xAbCdEfGhIjK --project-id my-gcp-project
```

Uses the `GOOGLE_APPLICATION_CREDENTIALS` environment variable, `gcloud` credentials, or the attached service account automatically.

### Authenticate with a service account key file

```bash
gcsi xAbCdEfGhIjK \
  --project-id my-gcp-project \
  --service-account-file /path/to/service-account-key.json
```

### Preview what would be imported (dry run)

```bash
gcsi xAbCdEfGhIjK --project-id my-gcp-project --dry-run
```

Prints the name of each secret that passes all filters without creating any records.

### Import only production secrets owned by the payments team

```bash
gcsi xAbCdEfGhIjK --project-id my-gcp-project \
  --name-starts-with prod- --tags team=payments
```

### Import a single known secret

```bash
gcsi xAbCdEfGhIjK --project-id my-gcp-project --name prod-stripe-api-key
```

### Import all database secrets in staging stored as `serverCredentials` records

```bash
gcsi xAbCdEfGhIjK --project-id my-gcp-project \
  --name-contains database \
  --tags env=staging \
  --record-type serverCredentials
```

### Dry-run a complex filter before committing

```bash
gcsi xAbCdEfGhIjK --project-id my-gcp-project \
  --name-starts-with prod- \
  --name-ends-with -creds \
  --tags env=prod,owner=platform \
  --dry-run
```

### Import using a service account key stored in a CI secret

```bash
# Decode the key from a CI environment variable and import
echo "$GCP_SA_KEY" > /tmp/sa-key.json
gcsi xAbCdEfGhIjK \
  --project-id my-gcp-project \
  --service-account-file /tmp/sa-key.json \
  --tags env=prod
rm /tmp/sa-key.json
```
