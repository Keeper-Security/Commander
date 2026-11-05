## PAM Project Import Commands
PAM Import command helps customers with thousands of managed companies to automate the creation of folders, gateways, machines, users, connections, tunnels and (optionally) rotations.

### Command line options

Initial Import.  
`pam project import --name=project1 --filename=/path/to/import.json [--dry-run]`

- `--name`, `-n` → Project name _(overrides `"project":""` from JSON)_
- `--filename`, `-f` → JSON file to load import data from.
- `--dry-run`, `-d` → Test import without modifying vault.


### Sample data (Discovery Playground)

Generate a ready-to-run PAM project that matches the [discovery-playground](https://github.com/Keeper-Security) docker stack — folders, KSM app, gateway, PAM configuration, sample records **and** a matching `docker-compose.yaml`.
`pam project import --sample-data [--name "My Playground"] [--dry-run]`

- `--sample-data`, `-s` → Generate sample data _(default project name: `Discovery Playground`)_.

What it creates:
- Vault records for MySQL, PostgreSQL, MariaDB, MSSQL, MongoDB, SSH (password + key), VNC, RDP, Telnet, OpenLDAP and a Remote Browser (RBI) resource.
- A `docker-compose.yaml` in the current directory (falls back to the OS temp dir if the cwd is not writable). If a `docker-compose.yaml` already exists it is written with a timestamp/random suffix instead of overwriting.
- A `docker-seccomp.json` next to the compose file (required by the gateway's `security_opt: seccomp:docker-seccomp.json`). It is written only if absent — the profile is identical for every run and is never overwritten.

All credentials are generated fresh per run and stored **both** in the vault records and in the generated compose — no secrets are hard-coded. They satisfy your enterprise password-complexity policy (a random password built to the policy's length / character-class / special-set rules, matching the Web Vault) and prefer characters that need no escaping in a shell, JSON or YAML — falling back to the policy's own special set when it requires one. On success the command prints exactly two lines: the absolute path of the compose file and the canonical seccomp URL.

The generated gateway uses `image: keeper/gateway:latest` and `security_opt: [seccomp:docker-seccomp.json, apparmor=unconfined]`, with its `GATEWAY_CONFIG` set to the base64 config of the gateway created during the import. Start the stack with `docker compose up -d`.

To re-download the seccomp profile manually:
```sh
curl -O https://raw.githubusercontent.com/Keeper-Security/KeeperPAM/refs/heads/main/gateway/docker-seccomp.json
```

Notes:
- **RBI** (Remote Browser) is a Keeper record only — it has no compose service.
- **OpenLDAP** (`server-openldap-1`, image `rroemhild/test-openldap`) uses image-fixed demo credentials (`cn=admin` / `GoodNewsEveryone`, domain `planetexpress.com`); the compose block carries no secrets and the demo users reset on container restart.
- **Telnet** (`server-telnet`, `ddhhz/nyancat-server`) has no authentication; the Keeper pamUser exists only for rotation/discovery testing.


Adding new PAM resources and users to an existing PAM configuration from an import file. The command validates folders and records, then creates only new items (match by title, existing records are skipped). The import JSON format is the same.  
`pam project extend --config=<uid_or_title> --filename=/path/to/import.json [--resources-folder=<uid_or_path>] [--users-folder=<uid_or_path>] [--dry-run]`

- `--config`, `-c` → PAM Configuration record UID or title.
- `--filename`, `-f` → JSON file to load import data from.
- `--resources-folder` → Existing folder (UID or folder path) for new resources. Overrides `folder_path` of resources in the JSON (a warning is printed).
- `--users-folder` → Existing folder (UID or folder path) for new users, incl. users nested in resources. Overrides `folder_path` of users in the JSON (a warning is printed).
- `--dry-run`, `-d` → Test import without modifying vault.

> **Notes:**
- Folder for new records: 1) `--resources-folder`/`--users-folder`, 2) `folder_path` in the JSON, 3) autodetect — folders named `<project> - Resources`/`<project> - Users`, otherwise the folder where existing resources (pamMachine, pamDatabase, pamDirectory, pamRemoteBrowser) or users (pamUser, login) live. If autodetect is ambiguous or finds nothing the command fails; add `folder_path` or use the options above.
- Use **`--dry-run`** to preview what would be created and to see detailed validation output without changing the vault. Import/extend dry-run prints the **batch plan** (creation tiers + Step 2 dispatch + `import_tail` on import) from `BatchPamImportEngine.simulate()` — no vault or DAG writes.
- If the command reports errors, run it again with **`--dry-run`** for more detailed error messages.

### Phase 0 skeleton (not batched)

Before `BatchPamImportEngine.run()`, import still runs sequentially:

1. Shared folder tree (`process_folders`) — classic SF or NSF
2. KSM application (`process_ksm_app`)
3. Gateway / controller (`process_gateway`)
4. PAM configuration (`process_pam_config`) — may stash `pam_config_object` for scripts deferred to **import tail**
5. **Batch engine** — `process_data` / extend equivalent (`1a→1b→1c→Step 2`)
6. **Import tail only** — [`import_tail.py`](import_tail.py): batched pamConfiguration cred scripts, then domain `pamDomainConfiguration` admin link (NSF-aware)

Extend skips steps 1–4 (config already exists) and runs its own domain-admin update after the engine when needed.

### Batch pipeline (import / extend)

Vault record creation uses **`BatchPamImportEngine`** ([`batch_pipeline.py`](batch_pipeline.py)):

1. **Step 0** — `assign_uids` / `assign_record_keys` (pre-assign UIDs and AES keys)
2. **Step 1a** — tiered `vault/records_add` via `pam_object_to_typed_record` + `pb_only=True` (chunks of 999)
3. **Step 1b** — deferred ref updates (`deferred_refs.py`): **Channel B** — strip/patch embedded `pamSettings` JSON refs via typed setters; **Channel A** — strip/patch typed `recordRef` / script `recordRef` + `record_links` via batch `records_update`
4. **Step 1c** — global `files_add` (300/chunk) + parallel PUTs + batch `records_update` for `fileRef` / rotation scripts ([`batch_attachments.py`](batch_attachments.py))
5. **Step 2** — shared deferred `TunnelDAG` + per-resource micro-order ([`batch_step2.py`](batch_step2.py)); tunnel validation via [`tunnel_setup.py`](tunnel_setup.py) helpers (**no** `PAMTunnelEditCommand.execute` on batch path); graph flush every 100 resources + final flush (`save_batch_count=50` chunked `add_data`, halves on HTTP 5xx down to 10)

**Folder routing:** Explicit ``folder_path`` in import JSON wins (import via ``safe_folder_map`` / nested path materialization; extend via ``path_to_folder_uid``). When unspecified: machine-like types → Resources; ``pamUser`` / ``login`` → Users.

**NSF (`--nsf`):** Phase 0 creates NSF folders; Step 1a uses ``vault/records/v3/add`` for NSF folder targets (classic ``vault/records_add`` otherwise); Step 1b uses ``vault/records/v3/update`` for NSF records; mid-pipeline sync preserves NSF folder keys.

**Layer-B hygiene:** at `run()` start, `clear_layer_b_feature_cache()` runs and a warning is logged if `KEEPER_DAG_LB_FALLBACK` is set (does not override that env var).

**Partial failure:** any `records_add` failure in a tier aborts before Step 1b/Step 2 and prints a per-record summary. A **Step 1b** or **Step 1c** `records_update` / upload failure also aborts before the next step.

**Import re-run after partial success:** manual only — use extend with explicit `"uid"` values or vault cleanup.

**PAM configuration scripts:** scripts without `additional_credentials` are uploaded during Phase 0 (`process_pam_config`). Scripts with resolved `recordRef`s run in the **import tail** after `engine.run()` via [`import_tail.py`](import_tail.py) (`run_import_tail` → batched `run_import_tail_config_scripts`; warn-only on failure). Domain admin link runs **after** cred scripts on the same config record (NSF uses `update_pam_record`).

**Dry-run (`simulate()`):** returns creation tiers, Step 2 dispatch, deferred ref/link plans, `link_count_warnings` when projected typed `record_links` per record exceed 100, and **`import_tail`** flags for post–Step 2 import-only work.

**Step 2 rotation:** `set_record_rotation` calls are throttled (10 per 10s pause) via [`rotation_throttle.py`](rotation_throttle.py). Schedule types are case-insensitive (`CRON` / `cron`). Extend/import skip rotation when `record_rotation_cache` already has the pamUser bound to the same resource.

**Sample-data (`--sample-data` / `-s`):** [`playground.py`](playground.py) builds the same Pam* object graph as a JSON import (fresh credentials + discovery-playground services), then runs **`BatchPamImportEngine`** — same Step 1a/1b/1c/2 path as file import. Dry-run prints `simulate()` plus compose/seccomp target paths. Compose YAML generation is unchanged (post-engine).



Import directly from a KCM/Guacamole database. Connects to the KCM database, extracts connections/users/groups, maps 130+ parameters, and feeds the result into the existing import engine.
`pam project kcm-import --db-host=HOST [OPTIONS]`

**Database (one of `--db-host` or `--docker-detect` required):**
- `--db-host HOST` → KCM database hostname.
- `--docker-detect` → Auto-detect credentials from Docker container. Discovers the KCM database container automatically, detects database type (mysql/postgresql), and resolves the container IP.
- `--docker-container NAME` → Specify Docker container name _(auto-discovered if omitted)_.
- `--db-port PORT` → Database port _(default: 3306 mysql, 5432 postgresql)_.
- `--db-name NAME` → Database name _(default: guacamole\_db)_.
- `--db-type {mysql,postgresql}` → Database type _(auto-detected with `--docker-detect`)_.
- `--db-user USER` → Database username _(default: guacamole\_user)_.
- `--db-password-record UID` → Keeper record UID or title containing DB password. If omitted, searches vault for candidates or prompts interactively.
- `--db-ssl` → Require SSL/TLS for database connection.
- `--allow-cleartext` → Allow unencrypted connection to remote database _(not recommended; required when connecting to a remote host without `--db-ssl`)_.

**Import:**
- `--name`, `-n` → Project name _(default: KCM-Import-TIMESTAMP)_.
- `--config`, `-c` → Existing PAM config UID or name to extend (skip project creation).
- `--folder-mode {ksm,exact,flat}` → Connection group mapping _(default: ksm)_.
- `--output`, `-o` → Save JSON to file for review before importing.
- `--gateway`, `-g` → Existing gateway UID or name _(interactive picker if omitted)_.
- `--max-instances N` → Set gateway pool size _(0 = skip, requires new gateway)_.

**Group Filtering:**
- `--list-groups` → List available KCM connection groups with resource/user counts, then exit.
- `--groups "Pattern1,Pattern2"` → Import only connections in matching groups. Supports fnmatch wildcards (`*`, `?`). Matches group name, full path, or any path segment.
- `--exclude-groups "Pattern1,Pattern2"` → Exclude connections in matching groups. Same wildcard support.

**Flags:**
- `--dry-run`, `-d` → Preview without vault changes (credentials redacted).
- `--skip-users` → Import connections only.
- `--include-disabled` → Include disabled KCM connections.
- `--include-credentials` → Include passwords in `--output` JSON _(redacted by default)_.
- `--yes`, `-y` → Skip confirmation prompt.
- `--estimate` → Show migration size estimate without importing.

**Throttling:**
- `--auto-throttle` / `--no-auto-throttle` → Enable/disable adaptive throttling with probe _(default: on)_.
- `--batch-size N` → Override records per batch.
- `--batch-delay N` → Override seconds between batches.

**Examples:**
```bash
# Full auto-detect from Docker (discovers container, db type, IP, credentials)
pam project kcm-import --docker-detect --dry-run

# List available connection groups before importing
pam project kcm-import --docker-detect --list-groups

# Import only specific connection groups
pam project kcm-import --docker-detect --groups "Production*,Staging*" --name "Prod Migration"

# Exclude groups from import
pam project kcm-import --db-host 10.0.0.5 --exclude-groups "Incomplete*,Test*"

# Import using password from vault record
pam project kcm-import --db-host db.example.com --db-password-record RECORD_UID --name "Prod KCM"

# Extend existing PAM config from PostgreSQL
pam project kcm-import --db-host pg.example.com --db-type postgresql --config "Existing Config"

# Auto-detect from Docker and save JSON for review
pam project kcm-import --docker-detect --output /tmp/kcm-review.json

# Specify Docker container and save with credentials
pam project kcm-import --docker-detect --docker-container kcm-db-1 --output /tmp/full.json --include-credentials
```

**Security:** DB passwords are never accepted as CLI arguments. Use `--db-password-record` (vault) or respond to the interactive prompt. Dry-run output redacts all credentials.

**Interactive Features:** When running interactively (no `--yes`):
- **Group picker** — shows connection groups with counts, lets you select by number
- **Gateway picker** — shows online gateways or create new
- **Password search** — searches vault for records matching "guacamole"/"kcm"
- **Import confirmation** — shows summary before proceeding

**Import Report:** After import, a structured report is printed to console and saved as a vault record at the project's top-level folder (alongside Resources/Users). The record includes:
- **Copyable custom fields**: `Deploy Gateway (copy & paste)` with full docker command, Gateway Token, Config UID, Gateway UID, KSM App UID, folder names
- `KCM-Import-Report.md` file attachment with the full report
- Per-record pass/fail breakdown by type (including nested users)
- Failed/skipped records with reasons
- Throttle statistics
- Redacted CLI command for reproducibility


### JSON format details
Text UI (TUI) elements (a.k.a. JSON Keys) match their Web UI counterparts so you can create the correponding record type in your web vault to help you visualize all options and possible values.

<details>
  <summary>General Import JSON Format</summary>

  ### Overview
  This only shows global JSON structure and each sub section is explained below _(expand by clicking on its heading)_
  > **Note:** Command line option `--name` overrides `"project"` key in JSON.
  ```json
{
	"project": "Project1",

	"shared_folder_users": {},
	"shared_folder_resources": {},

	"pam_configuration": {},
	"pam_data": {
		"resources": [
			{"type": "pamDatabase"},
			{"type": "pamDirectory"},
			{"type": "pamMachine"},
			{"type": "pamRemoteBrowser"}
		],
		"users": [
			{"type": "pamUser"},
			{"type": "login"}
		]
	}
}
```
</details>
<details>
  <summary>Shared Folders Format</summary>

  The format is similar for both `shared_folder_users` and `shared_folder_resources`
  > **Note:** Users and Teams must exist in your vault for import to succeed.  
```json
{
	"shared_folder_users": {
		"manage_users": true,
		"manage_records": true,
		"can_edit": true,
		"can_share": true,
		"permissions": [
			{ "name": "IT Team", "manage_users": false, "manage_records": false },
			{ "name": "user1@example.com", "manage_users": true, "manage_records": true }
		]
	},
	"shared_folder_resources": {
		"permissions": [{ "name": "Shared Folder Admins Team", "manage_users": true, "manage_records": true }]
	},
}
```
</details>

#### PAM Configurations:
_You can have only one `pam_configuration` section and the only required parameter is `environment` (`"local"`, `"aws"`, `"azure"`, `"domain"`, `"gcp"`, or `"oci"`) Expand the corresponding section below to see specific details._
  > **Note:** Full details are shown on `pam_configuration: local` but the common section on top is the same across all configuration types. _(ex. local specific configuration starts with `network_id`/`network_cidr`)_  
<details>
<summary>pam_configuration: local</summary>

```json
{
	"pam_configuration": {
		"environment": "local",

		"title": "Project1 Local PAM Configuration",
		"gateway_name": "Project1 Gateway",

		"connections": "on",
		"rotation": "on",
		"tunneling": "on",
		"ai_threat_detection": "off",
		"ai_terminate_session_on_detection": "off",
		"remote_browser_isolation": "on",
		"graphical_session_recording": "off",
		"text_session_recording": "off",

		"port_mapping": ["2222=ssh", "33306=mysql"],
		"default_rotation_schedule": { "type": "CRON", "cron": "30 18 * * *" },
		"scripts": [
			{ "file": "/path/to/script1.ps1", "script_command": "pwsh", "additional_credentials": "user2"] },
			{ "file": "/path/to/script2.ps1", "script_command": "pwsh" },
			{ "file": "/path/to/script2.sh" }
		],
		"attachments": ["/path/to/file1.txt", "/path/to/file2.bin"],

		"network_id": "project1-net",
		"network_cidr": "192.168.1.0/28"
	}
}
```
</details>
<details>
<summary>pam_configuration: aws</summary>

```json
{
	"pam_configuration": {
		"environment": "aws",
		"title": "Project1 AWS PAM Configuration",

		"aws_id": "my-aws_id",
		"aws_access_key_id": "my-aws_access_key_id",
		"aws_secret_access_key": "my-aws_secret_access_key",
		"aws_region_names": ["us-east-1", "us-west-2"]
	}
}
```
</details>
<details>
<summary>pam_configuration: azure</summary>

```json
{
	"pam_configuration": {
		"environment": "azure",
		"title": "Project1 Azure PAM Configuration",

		"az_entra_id": "my-az_entra_id",
		"az_client_id": "my-az_client_id",
		"az_client_secret": "my-az_client_secret",
		"az_subscription_id": "my-az_subscription_id",
		"az_tenant_id": "my-az_tenant_id",
		"az_resource_groups": ["rg-WebApp1-Dev", "rg-WebApp1-Prod"]
	}
}
```
</details>
<details>
<summary>pam_configuration: domain</summary>

```json
{
	"pam_configuration": {
		"environment": "domain",
		"title": "Project1 Domain PAM Configuration",

		"dom_domain_id": "my-domain_id",
		"dom_hostname": "my-hostname",
		"dom_port": "my-port",
		"dom_use_ssl": true,
		"dom_scan_dc_cidr": true,
		"dom_network_cidr": "192.168.1.0/28",
		"dom_user_match": "OU=Office Users,DC=example,DC=com",
		"dom_administrative_credential": "admin1"
	}
}
```
</details>
<details>
<summary>pam_configuration: gcp</summary>

```json
{
	"pam_configuration": {
		"environment": "gcp",
		"title": "Project1 GCP PAM Configuration",

		"gcp_id": "my-gcp_id",
		"gcp_service_account_key": "my-gcp_service_account_key",
		"gcp_google_admin_email": "my-gcp_google_admin_email",
		"gcp_region_names": ["us-east1", "us-central1"]
	}
}
```
</details>
<details>
<summary>pam_configuration: oci</summary>

```json
{
	"pam_configuration": {
		"environment": "oci",
		"title": "Project1 OCI PAM Configuration",

		"oci_id": "my-oci_id",
		"oci_admin_id": "my-oci_admin_id",
		"oci_admin_public_key": "my-oci_admin_public_key",
		"oci_admin_private_key": "my-oci_admin_private_key",
		"oci_tenancy": "my-oci_tenancy",
		"oci_region": "my-oci_region"
	}
}
```
</details>

#### Resources (users, machines etc.):
Each Machine (pamMachine, pamDatabase, pamDirectory) can specify **Administrative Credentials** (admin user) and **Launch Credentials** (the credentials used to establish the protocol connection). Both are identified by title or login/username of a pamUser (e.g. `"administrative_credentials": "admin1"`, `"launch_credentials": "user1"`). pamUser and pamRemoteBrowser do not have launch credentials; pamRemoteBrowser uses `pam_settings.connection.autofill_credentials` for RBI login.
- **Machines** are defined in `pam_data.resources` where each machine can have its own list of `"users": []` one of which is the admin user for that machine. Users that don't belong to a single machine are into global `pam_data.users` section (record type: `login`, `pamUser` for NOOP rotation or shared across multiple machines /ex. same user for ssh, vnc, rdp etc./)
  > **Note 1:** `pam_settings` _(options, connection)_ are explained only in pamMachine section below (per protocol) but they are present in all machine types.  
  > **Note 2:** `attachments` and `scripts` examples are in `pam_configuration: local` section.  
  > **Note 3:** Post rotation scripts (a.k.a. `scripts`) are executed in following order: `pamUser` scripts after any **successful** rotation for that user, `pamMachine` scripts after any **successful** rotation on the machine and `pamConfiguration` scripts after any rotation using that configuration.
  > **Note 4:** Post-rotation scripts can only be attached by the **record owner**. Non-owners will see an upload error during import or when using `pam rotate script add`.
  > **Note 5:** When `allow_supply_user` is false and JIT ephemeral is not used, vault may require a launch credential; import can provide it via `launch_credentials` in the resource's `connection` block.
  > **Note 6:** RBI (pamRemoteBrowser) `connection` supports `allow_supply_user` (true/false; omit to leave unset), `accept_language` (e.g. `en-US,en;q=0.9`) and `suppress_js_dialogs` (true/false). `clipboard_buffer_size` - the clipboard data size limit: `256kb`, `1mb`, `10mb` or `50mb` (case-insensitive; stored in bytes) - is supported by RBI and by RDP, VNC, Telnet, SSH and all database protocols (not Kubernetes). `default` or omitted leaves it unset; any other value is ignored with a warning (use `--dry-run` to see these warnings before importing).
  > **Note 7:** `pam_settings.port_forward` (remote/local port, Keeper proxy gates `allow_keeper_db_proxy` / `allow_keeper_rdp_proxy` / `allow_keeper_ssh_proxy`) is explained in the _Port forwarding and Keeper proxies_ section below, including the validation that runs before any vault write.
  > **Note 8:** SFTP settings (RDP, SSH, VNC) are in `pam_settings.connection.sftp`. RDP/VNC: `enable_sftp`, `sftp_resource` (title or login of the SFTP server machine), `sftp_user_credentials` (title or login of the pamUser), `sftp_root_directory`, `sftp_upload_directory`, `sftp_keepalive_interval`, `sftp_timeout` (SFTP connection timeout in whole **seconds**, same unit as KCM `sftp-timeout`; the KCM default is 10 seconds when omitted; `0` and non-numeric values are not written; the sign is ignored, as for `sftp_keepalive_interval`), `sftp_disable_download`, `sftp_disable_upload`. SSH reuses its own connection and credentials, so it only takes `enable_sftp`, `sftp_root_directory`, `sftp_disable_download` and `sftp_disable_upload`; Telnet and other protocols have no SFTP. All sftp keys are added even when `enable_sftp` is not true, with a warning that they stay disabled until SFTP is enabled. Other warnings: RDP/VNC with `enable_sftp` true but no `sftp_resource`, and keys the protocol does not support (ignored).  
  > **Note 9:** VNC display, clipboard and audio options (`pam_settings.connection`, protocol `vnc`): `read_only` (no input accepted), `swap_red_blue` (fixes wrong colors: blue shown as orange/red), `force_lossless` (lossless compression only), `cursor` (`local` default | `remote`), `color_depth` (bits per pixel: `8`, `16`, `24` or `32`; omitted = server decides), `compress_level` (whole number 0-9: 0 = no compression/fastest, 9 = maximum compression), `quality_level` (whole number 0-9: JPEG quality for the `tight` encoding, 0 = lowest, 9 = best), `encodings` (space separated list of `copyrect`, `hextile`, `raw`, `rre`, `tight`, `zrle`, `ultra`, `zlib`, `corre`; a JSON list is also accepted; unknown names are skipped with a warning; omitted = plugin default order `zrle ultra copyrect hextile zlib corre rre raw`), `clipboard_encoding` (`ISO8859-1` default | `UTF-8` | `UTF-16` | `CP1252` | `MacRoman`), `clipboard_buffer_size` (`256kb` = 262144 bytes, `1mb` = 1048576, `10mb` = 10485760, `50mb` = 52428800), `enable_audio` (opens a second PulseAudio connection) and `audio_servername` (PulseAudio server name; default device when omitted). Booleans accept true/false. Invalid values are ignored with a warning. The Web Vault UI names the compression, quality and encodings options differently, so the Vault does not show the values set here.  
  > **Note 10:** SSH terminal and session options (`pam_settings.connection`, protocol `ssh`): `font_name` (font family name, free text), `read_only` (no input accepted), `backspace` (`127` = Delete, Ctrl-? - default | `8` = Backspace, Ctrl-H), `terminal_type` (the `TERM` value sent to the server, free text; the common values are `xterm`, `xterm-256color`, `vt220`, `vt100`, `ansi`, `linux` - other values are written with a warning because the target host may not know them), `locale` (the `$LANG` value, e.g. `en_US.UTF-8`), `timezone` (the `$TZ` value, an IANA name e.g. `America/New_York`), `server_alive_interval` (whole seconds between SSH keepalive packets: `0` = disabled, the default; the minimum is `2`, `1` is stored as `2` with a warning; negative values are ignored with a warning), plus `clipboard_buffer_size` (`256kb` = 262144 bytes, `1mb` = 1048576, `10mb` = 10485760, `50mb` = 52428800). Invalid values are ignored with a warning.  
  > **Note 11:** RDP options (`pam_settings.connection`, protocol `rdp`): `initial_program` (full path of the program to run after connecting), `client_name` (shown on Windows servers as `%CLIENTNAME%`; guacd truncates it to 32 bytes - a guacd limitation, longer names are written unchanged with a warning), `server_layout` (keyboard layout: `cs-cz-qwertz`, `da-dk-qwerty`, `de-ch-qwertz`, `de-de-qwertz`, `en-gb-qwerty`, `en-us-qwerty` - the default, `es-es-qwerty`, `es-latam-qwerty`, `failsafe` - Unicode events, `fr-be-azerty`, `fr-ca-qwerty`, `fr-ch-qwertz`, `fr-fr-azerty`, `hu-hu-qwertz`, `it-it-qwerty`, `ja-jp-qwerty`, `nb-no-qwerty`, `no-no-qwerty`, `pl-pl-qwerty`, `pt-br-qwerty`, `pt-pt-qwerty`, `ro-ro-qwerty`, `sv-se-qwerty`, `tr-tr-qwerty`; an unknown name is skipped with a warning and guacd uses `en-us-qwerty`), `timezone` (IANA name, e.g. `America/New_York`; defaults to the client timezone), `enable_touch` (multi-touch), `console` (connect to the console/admin session), `width`, `height` (pixels) and `dpi` (whole numbers greater than 0; defaults follow the connecting client; guacd rounds the width down to a multiple of 4), `color_depth` (bits per pixel: `8`, `16`, `24` or `32`; guacd always uses 32 while the RDP Graphics Pipeline is enabled, which is the default, so lower values are ignored), `force_lossless` (lossless compression only), `read_only` (no input accepted), `normalize_clipboard` (`preserve` = unchanged, `unix` = LF line endings, `windows` = CRLF line endings), `console_audio`, `enable_audio_input` (microphone), `enable_printing`, `printer_name` (name of the redirected printer; defaults to `Guacamole Printer`), performance flags `enable_theming`, `enable_font_smoothing`, `enable_desktop_composition`, `enable_menu_animations` (all off by default) and `disable_bitmap_caching`, `disable_offscreen_caching`, `disable_glyph_caching` (true turns that cache off), `remote_app` (RemoteApp to start - on Windows servers the published name needs the `||` prefix, e.g. `||notepad`), `remote_app_dir` (working directory) and `remote_app_args` (command-line arguments). Booleans accept true/false. Invalid values are ignored with a warning.  
  > **Note 12:** Telnet options (`pam_settings.connection`, protocol `telnet`): `username_regex` and `password_regex` are POSIX extended regular expressions (case-insensitive) that guacd matches against the server output to find the login and password prompts (defaults `[Ll]ogin:` and `[Pp]assword:`; used only when a username is set). `login_success_regex` and `login_failure_regex` detect a successful or failed login with the same kind of expression - give both or neither: guacd ignores a single one (the import warns and writes it anyway). The patterns are not validated by the import. `font_name` (font family, default `monospace`), `font_size` (points: 8, 9, 10, 11, 12, 14, 18, 24, 30, 36, 48, 60, 72 or 96, default 12; the closest value is used), `color_scheme` (`black-white`, `gray-black`, `green-black` or `white-black`), `scrollback` (rows, default 1000), `read_only` (no input accepted), `backspace` (`127` = Delete, Ctrl-? - default | `8` = Backspace, Ctrl-H), `terminal_type` (the `TERM` value sent to the server, default `linux`; common values `xterm`, `xterm-256color`, `vt220`, `vt100`, `ansi`, `linux` - other values are written with a warning because the target host may not know them) and `clipboard_buffer_size` (`256kb` = 262144 bytes, `1mb` = 1048576, `10mb` = 10485760, `50mb` = 52428800). Telnet has no SFTP: an `sftp` object on a Telnet resource is ignored with a warning. Invalid values are ignored with a warning.  
  > **Note 13:** Kubernetes options (`pam_settings.connection`, protocol `kubernetes`): `use_ssl` (use SSL/TLS for the connection to the Kubernetes API server, default false), `ignore_server_cert` (accept a server certificate that cannot be validated), `ca_certificate`, `client_certificate` and `client_key` (PEM-encoded), `namespace` (the namespace of the pod), `pod_name` (the pod to connect to - required), `container` (the container inside the pod), `exec_command` (the command to run in the container; omitted = the default shell), `font_name` (font family, default `monospace`), `font_size` (points: 8, 9, 10, 11, 12, 14, 18, 24, 30, 36, 48, 60, 72 or 96, default 12), `color_scheme` (`black-white`, `gray-black`, `green-black` or `white-black`), `scrollback` (rows, default 1000), `read_only` (no input accepted) and `backspace` (`127` = Delete, Ctrl-? - default | `8` = Backspace, Ctrl-H). Invalid values are ignored with a warning. The Web Vault names the exec command option differently, so the Vault does not show the value set here.  
  > **Note 14:** Database options (`pam_settings.connection`, protocols `mysql`, `postgresql`, `sql-server`, `mariadb`, `oracle`, `mongodb`, `redis`, `elasticsearch`, `clickhouse`, `dynamodb`): `default_database` (database name), `disable_csv_export` / `disable_csv_import` (true blocks CSV download / upload), `clipboard_buffer_size` (`256kb` = 262144 bytes, `1mb` = 1048576, `10mb` = 10485760, `50mb` = 52428800). For `mysql`, `postgresql` and `sql-server` only (the CLI-capable protocols): `font_name` (font family, default `monospace`), `font_size` (points, default 12), `color_scheme` (`black-white`, `gray-black`, `green-black` or `white-black`), `scrollback` (rows, default 1000) and `read_only` (no input accepted). `db_connection_method` (`cli` = guacd database client, `keeperDB` = KeeperDB proxy session, `both` = the user chooses at launch; case-insensitive): for `mysql`, `postgresql` and `sql-server` it is written as given and nothing is written when omitted (CLI); the other seven protocols are KeeperDB-only, so the record always gets `keeperDB` - any other value is replaced with `keeperDB` and a warning says so. `session_persistence` (`none` = incognito, no profile storage; `user` = profile stored per user and resource; `resource` = one profile shared per resource) is written as `rbiSettings.sessionPersistence` and only applies to KeeperDB sessions (`keeperDB` or `both`); with `cli` it has no effect and a warning is printed. The pamDatabase `database_type` has nine values (the Web Vault "Database Type" list): `postgresql`, `postgresql-flexible`, `mysql`, `mysql-flexible`, `mariadb`, `mariadb-flexible`, `mssql`, `oracle` and `mongodb`. `redis`, `elasticsearch`, `clickhouse` and `dynamodb` are chosen through `pam_settings.connection.protocol` instead (leave `database_type` out; `dynamodb` also needs `provider_region`) - the Gateway uses `database_type` first and `connection.protocol` only when `database_type` is empty, so a `database_type` that differs from the connection protocol gets a warning. A KeeperDB-only database resource that has no `pam_settings.connection` at all gets a warning that shows the connection to add, e.g. `"pam_settings": { "connection": { "protocol": "oracle", "db_connection_method": "keeperDB" } }`. Invalid values are ignored with a warning.  

JIT and KeeperAI settings below are shared across all resource types (pamMachine, pamDatabase, pamDirectory) except User and RBI (pamRemoteBrowser) records. **Workflow** (approvals / checkout / temporal restrictions) is supported on all four resource types: pamMachine, pamDatabase, pamDirectory, **and** pamRemoteBrowser.

<details>
<summary>Just-In-Time Access (JIT)</summary>

[Just-In-Time Access (JIT)](https://docs.keeper.io/en/keeperpam/privileged-access-manager/getting-started/just-in-time-access-jit) - By implementing JIT access controls, organizations can significantly reduce their attack surface by ensuring that privileged access is only granted when needed, for the duration required, and with appropriate approvals.

**How to Configure:** Import JSON follows Keeper Vault web UI (JIT tab on resource records). Configure the elevation settings (Ephemeral account or Group/Role elevation) using `pam_settings.options.jit_settings`. Use `pam_directory_record` to reference a pamDirectory by its `title` from `pam_data.resources[]` (for domain account type):

```json
{
    "jit_settings": {
        "create_ephemeral": true,
        "elevate": true,
        "_comment_method": "elevation methods: <group|role>",
        "elevation_method": "group",
        "elevation_string": "arn:aws:iam::12345:role/Admin",
        "base_distinguished_name": "OU=Users,DC=example,DC=net",
        "_comment_ephemeral_account_types": "<linux|mac|windows|domain>",
        "ephemeral_account_type": "linux",
        "_comment_pam_directory_record": "by title, requried if ephemeral_account_type: domain",
        "pam_directory_record": "PAM AD1"
    }
}
```
</details>
<details>
<summary>KeeperAI</summary>

[KeeperAI](https://docs.keeper.io/en/keeperpam/privileged-access-manager/keeperai) - AI-powered threat detection for KeeperPAM privileged sessions. KeeperAI is an Agentic AI-powered threat detection system that automatically monitors and analyzes KeeperPAM privileged sessions to identify suspicious or malicious behavior.

**PAM Configuration Settings** (in `pam_configuration`):
- `ai_threat_detection`
- `ai_terminate_session_on_detection`

**Activating Threat Detection on a Resource:** Import JSON follows Keeper Vault web UI (AI tab on resource records). Session recordings (graphical and/or text) must be enabled for KeeperAI to work. Edit PAM Settings for your selected resource: enable `ai_threat_detection` and `ai_terminate_session_on_detection` in `pam_settings.options`, then add `pam_settings.options.ai_settings` with your risk-level rules:

```json
{
    "pam_settings": {
        "options": {
            "graphical_session_recording": "on",
            "text_session_recording": "on",
            "ai_threat_detection": "on",
            "ai_terminate_session_on_detection": "on",
            "ai_settings": {
                "risk_levels": {
                    "critical": {
                        "ai_session_terminate": true,
                        "activities": {
                            "allow": [
                                {"tag": "mount"},
                                {"tag": "umount"}
                            ],
                            "deny": [
                                {"tag": "iptables"},
                                {"tag": "wget | sh"}
                            ]
                        }
                    },
                    "high": {
                        "ai_session_terminate": true,
                        "activities": {
                            "allow": [
                                {"tag": "\\bmount\\b"},
                                {"tag": "\\bumount\\b"}
                            ],
                            "deny": [
                                {"tag": "kill -9"},
                                {"tag": "\\bkill\\s+-9\\b.*"}
                            ]
                        }
                    },
                    "medium": {
                        "ai_session_terminate": true,
                        "activities": {
                            "allow": [
                                {"tag": "chmod"},
                                {"tag": "chown"}
                            ],
                            "deny": [
                                {"tag": "bash"},
                                {"tag": "dash"}
                            ]
                        }
                    },
                    "low": {
                        "ai_session_terminate": false,
                        "activities": {
                            "allow": [
                                {"tag": "\\bwget\\b"},
                                {"tag": "\\bchmod\\b"}
                            ]
                        }
                    }
                }
            }
        }
    }
}
```
</details>
<details>
<summary>Workflow (Approvals, Checkout, Temporal Access)</summary>

Workflow controls how privileged access to a resource is gated: how many approvals are needed, whether sessions require check-out, MFA, reason/ticket, what time windows access is allowed in, and who can approve (with optional escalation). Workflow is applied via the Keeper Router **after** the resource record and DAG/JIT/AI steps are complete and is not stored on the record itself.

**How to Configure:** Add `pam_settings.options.workflow` to any pamMachine, pamDatabase, pamDirectory, or pamRemoteBrowser. The workflow object maps directly to the Web Vault's "Workflow" tab on a resource record.

```json
{
    "pam_settings": {
        "options": {
            "workflow": {
                "approvals_needed": 2,
                "checkout_needed": true,
                "start_access_on_approval": false,
                "require_reason": true,
                "require_ticket": false,
                "require_mfa": true,
                "access_duration": "8h",
                "allowed_times": {
                    "allowed_days": ["mon", "tue", "wed", "thu", "fri"],
                    "time_ranges": [
                        { "start": "09:00", "end": "17:30" }
                    ],
                    "timezone": "America/New_York"
                },
                "approvers": [
                    {
                        "principal": { "type": "user", "email": "primary.approver@example.com" },
                        "escalation": false
                    },
                    {
                        "principal": { "type": "user", "email": "second.approver@example.com" },
                        "escalation": false
                    },
                    {
                        "principal": {
                            "type": "team",
                            "team_uid_base64url": "REPLACE_TEAM_UID_BASE64URL"
                        },
                        "escalation": true,
                        "escalation_after": "45m"
                    }
                ]
            }
        }
    }
}
```

**Field reference:**
- `approvals_needed` *(int, default `0`)* — number of approvals required to grant access.
- `checkout_needed` *(bool, default `false`)* — require explicit check-out before launching a session.
- `start_access_on_approval` *(bool, default `false`)* — start the access window the moment approval is granted (rather than at session launch).
- `require_reason` / `require_ticket` *(bool, default `false`)* — prompt the user for a reason / ticket reference at request time.
- `require_mfa` *(bool, default `false`)* — require MFA at session launch.
- `access_duration` *(string, default `"1d"`)* — how long approved access remains valid. Accepts `Xm` / `Xh` / `Xd` (e.g. `"30m"`, `"8h"`, `"2d"`); a bare integer is interpreted as minutes. Must be positive.
- `allowed_times.allowed_days` *(list of strings)* — restrict access to these weekdays. Accepts 3-letter (`mon`..`sun`) or full names (`monday`..`sunday`), case-insensitive.
- `allowed_times.time_ranges` *(list of `{start, end}` objects)* — one or more allowed daily time windows in `HH:MM` (24-hour) format. **Multiple ranges per day are supported.** A single range whose `end` is earlier than its `start` (e.g. an overnight `22:00–06:00`) **should be split into two ranges** that both fall inside one day (e.g. `22:00–23:59` and `00:00–06:00`)
- `allowed_times.timezone` *(string)* — IANA timezone name (e.g. `"UTC"`, `"America/New_York"`). **Required when `time_ranges` is non-empty.**
- `approvers[]` — list of approver entries.
  - `principal.type` — `"user"` or `"team"`.
  - For users: `principal.email` (must exist in the enterprise).
  - For teams: `principal.team_uid_base64url` (the team's vault UID, base64url-encoded; validated against the local team cache during import — unknown UIDs fail in dry-run).
  - `escalation` *(bool)* — whether this approver is in the escalation chain.
  - `escalation_after` *(duration string, optional)* — wait this long before escalating to this approver. **Requires `escalation: true`.**

**Behavior notes:**
- **Trivial workflow is a no-op.** If none of `approvals_needed > 0`, `checkout_needed`, `require_mfa`, `start_access_on_approval`, `allowed_times.allowed_days`, or `allowed_times.time_ranges` is set, the workflow block is treated as absent and no Router call is made.
- **Pre-flight validation runs in `--dry-run`.** Bad durations, malformed `HH:MM`, missing timezone, escalation rule violations, and unknown team UIDs are reported during dry-run before any vault writes.
- **Dry-run skips the Router calls.** Workflow is applied (Router create/update + approver reconcile) only on a real run.
- **`extend` only applies workflow to newly created resources** (existing resources are not touched).
</details>
<details>
<summary>Port forwarding and Keeper proxies (pam_settings.port_forward)</summary>

`pam_settings.port_forward` (tunneling) is present on pamMachine, pamDatabase and pamDirectory; it sits next to `connection`, not inside it. pamRemoteBrowser has no port forward settings. The keys are written to the record's `pamSettings.portForward`:

| Key | Type | Notes |
|---|---|---|
| `port` | string | Remote tunnel port override (the Gateway reads it) |
| `reuse_port` | boolean | Reuse the last local port (Vault clients only) |
| `use_specified_local_port` | boolean | Use `local_port` instead of a generated local port (Vault clients only). **Requires `local_port`** |
| `local_port` | string/number | Local port, 1-65535 (Vault clients only) |
| `allow_keeper_db_proxy` | boolean | KeeperDB Proxy - **MySQL, MariaDB, PostgreSQL, SQL Server, Oracle, DynamoDB** (not MongoDB) |
| `allow_keeper_rdp_proxy` | boolean | KeeperRDP Proxy - **RDP** machines |
| `allow_keeper_ssh_proxy` | boolean | KeeperSSH Proxy - **SSH** machines |

```json
{
    "type": "pamDatabase",
    "title": "PAM MySQL",
    "pam_settings": {
        "options": { "tunneling": "on", "connections": "on" },
        "port_forward": {
            "port": "3306",
            "use_specified_local_port": true,
            "local_port": "13306",
            "allow_keeper_db_proxy": true
        },
        "connection": { "protocol": "mysql", "port": "3306", "launch_credentials": "db-user1" }
    }
}
```

**Validation** - checked for the whole file *before* anything is written to the vault (app, folders, records, DAG), also in `--dry-run`, for both `pam project import` and `pam project extend`. All problems are listed together and the command aborts without changes. Errors:
- a proxy gate on a protocol it does not support (RDP gate on non-RDP, SSH gate on non-SSH, DB gate on a protocol outside the list above) or without `connection.protocol`;
- a proxy gate without a launch credential - set `connection.launch_credentials` (not needed with `connection.allow_supply_user`, `allow_supply_host` or `jit_settings.create_ephemeral`; ephemeral JIT does not count for DynamoDB);
- `use_specified_local_port` without `local_port`, or a `local_port` that is not a valid port number;
- `connection.allow_keeper_db_proxy` / `connection.allowKeeperDBProxy` - the KeeperDB Proxy gate moved to `port_forward.allow_keeper_db_proxy`.

`port_forward` settings on a resource with `options.tunneling` set to `off` only produce a warning: the values are still stored (like switching the Vault toggle off and on again) but have no effect while tunneling is off.

**Notes:**
- The proxy gates are read by the Gateway; the Web Vault shows the KeeperRDP / KeeperSSH proxy switches from Vault 18.7.0. `use_specified_local_port`, `local_port` and `reuse_port` are used by Vault clients only (the Gateway and `pam tunnel` ignore them).
- `pam tunnel edit --keeper-db-proxy` and `--keeper-proxy` write the KeeperDB Proxy gate to `portForward.allowKeeperDBProxy` only. A legacy `connection.allowKeeperDBProxy` on existing records is left as is (the Gateway still honours it as a fallback).
</details>
<details>
<summary>pam_data.resources.pamMachine (RDP)</summary>

```json
{
    "type": "pamMachine",
    "title": "PAM RDP Machine",
    "notes": "RDP Machine1",
    "host": "127.0.0.1",
    "port": "3389",
    "_comment_port": "administrative port",
    "ssl_verification" : true,
    "operating_system": "Windows",
    "instance_name": "InstanceName",
    "instance_id": "InstanceId",
    "provider_group": "ProviderGroup",
    "provider_region": "us-east1",
    "otp": "otpauth://totp/Example:alice3@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ExampleApp3",
    "attachments": [],
    "scripts": [],
    "pam_settings": {
        "options" : {
            "rotation": "on",
            "connections": "on",
            "tunneling": "on",
            "remote_browser_isolation": "on",
            "graphical_session_recording": "on",
            "ai_threat_detection": "off",
            "ai_terminate_session_on_detection": "off",
            "jit_settings": {},
            "ai_settings": {},
            "workflow": {}
        },
        "allow_supply_host": false,
        "port_forward": {
            "_comment": "Tunneling settings",
            "_comment_port": "remote tunneling port",
            "port": "2222",
            "reuse_port": true,
            "_comment_proxy": "optional: allow_keeper_rdp_proxy (RDP) - see Port forwarding and Keeper proxies above",
            "allow_keeper_rdp_proxy": true
        },
        "connection" : {
            "_comment": "Connections settings per protocol - RDP",
            "protocol": "rdp",
            "_comment_port": "connection port",
            "port": "2222",
            "allow_supply_user": true,
            "administrative_credentials": "admin1",
            "launch_credentials": "user1",
            "recording_include_keys": true,
            "disable_copy": true,
            "disable_paste": true,
            "clipboard_buffer_size": "10mb",
            "_comment_clipboard_buffer_size": "default | 256kb | 1mb | 10mb | 50mb (all protocols with clipboard settings, not Kubernetes)",
            "_comment_security": "any|nla|tls|vmconnect|rdp",
            "security": "any",
            "disable_authentication": true,
            "ignore_server_cert": true,
            "load_balance_info": "<LB Info/Cookie>",
            "preconnection_id": "<RDP Source ID>",
            "preconnection_blob": "Preconnection BLOB: <VM ID>",
            "sftp": {
                "enable_sftp": true,
                "sftp_resource": "Machine2",
                "sftp_user_credentials": "sftp user2",
                "sftp_root_directory": "/opt/sftp",
                "sftp_upload_directory": "/opt/uploads",
                "sftp_keepalive_interval": 12,
                "sftp_timeout": 30,
                "sftp_disable_download": false,
                "sftp_disable_upload": false
            },
            "_comment_sftp": "RDP/VNC sftp object: see section 'SFTP settings (RDP, SSH, VNC)'; all sftp keys are added even when enable_sftp is not true (warning: they stay disabled until SFTP is enabled)",
            "disable_audio": true,
            "resize_method": "display-update",
            "_comment_resize_method": "RDP resize-method: \"\" (empty) = no dynamic resizing | display-update (default when omitted) | reconnect (replaces the removed disable_dynamic_resizing)",
            "enable_full_window_drag": true,
            "enable_wallpaper": true,
            "_comment_drive_redirection_path": "none|user|resource",
            "drive_redirection_path": "resource",
            "initial_program": "C:\\Windows\\notepad.exe",
            "client_name": "keeper-client",
            "_comment_server_layout": "keyboard layout, e.g. en-us-qwerty (default) | en-gb-qwerty | de-de-qwertz | fr-fr-azerty | ja-jp-qwerty | failsafe",
            "server_layout": "en-us-qwerty",
            "timezone": "America/New_York",
            "enable_touch": false,
            "console": false,
            "_comment_display": "width/height in pixels and dpi: whole numbers greater than 0",
            "width": 1920,
            "height": 1080,
            "dpi": 96,
            "_comment_color_depth": "bits per pixel: 8 | 16 | 24 | 32. guacd uses 32 while the RDP Graphics Pipeline is enabled (default) and ignores other values",
            "color_depth": 32,
            "force_lossless": false,
            "read_only": false,
            "_comment_normalize_clipboard": "preserve | unix (LF line endings) | windows (CRLF line endings)",
            "normalize_clipboard": "preserve",
            "console_audio": false,
            "enable_audio_input": false,
            "enable_printing": false,
            "printer_name": "Keeper Printer",
            "enable_theming": false,
            "enable_font_smoothing": true,
            "enable_desktop_composition": false,
            "enable_menu_animations": false,
            "disable_bitmap_caching": false,
            "disable_offscreen_caching": false,
            "disable_glyph_caching": false,
            "_comment_remote_app": "Windows servers: the published RemoteApp name needs the || prefix, e.g. ||notepad",
            "remote_app": "||notepad",
            "remote_app_dir": "C:\\Users\\Public",
            "remote_app_args": "/safe"
        }
    }
}
```
</details>
<details>
<summary>pam_data.resources.pamMachine (SSH)</summary>

```json
{
	"type": "pamMachine",
	"title": "PAM SSH Machine",
	"notes": "SSH Machine1",
	"host": "127.0.0.1",
	"port": "3389",
	"ssl_verification" : true,
	"operating_system": "Windows",
	"instance_name": "InstanceName",
	"instance_id": "InstanceId",
	"provider_group": "ProviderGroup",
	"provider_region": "us-east1",
	"otp": "otpauth://totp/Example:alice3@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ExampleApp3",
	"attachments": [],
	"scripts": [],
	"pam_settings": {
		"options" : {
			"rotation": "on",
			"connections": "on",
			"tunneling": "on",
			"remote_browser_isolation": "on",
			"graphical_session_recording": "on",
			"text_session_recording": "on",
			"ai_threat_detection": "off",
			"ai_terminate_session_on_detection": "off"
		},
		"allow_supply_host": false,
		"port_forward": {
			"_comment": "Tunneling settings",
			"port": "2222",
			"reuse_port": true,
			"allow_keeper_ssh_proxy": true
		},
		"connection" : {
			"_comment": "Connections settings per protocol - SSH",
			"protocol": "ssh",
			"port": "2222",
			"allow_supply_user": true,
			"administrative_credentials": "admin1",
			"launch_credentials": "user1",
			"recording_include_keys": true,
			"disable_copy": true,
			"disable_paste": true,
			"color_scheme": "gray-black",
			"font_size": "18",
			"scrollback": 5000,
			"public_host_key": "<Public Host Key (Base64)>",
			"command": "/bin/bash",
			"font_name": "Menlo",
			"read_only": false,
			"_comment_backspace": "127 = Delete (Ctrl-?, default) | 8 = Backspace (Ctrl-H)",
			"backspace": "127",
			"terminal_type": "xterm-256color",
			"locale": "en_US.UTF-8",
			"timezone": "America/New_York",
			"_comment_server_alive_interval": "seconds between SSH keepalive packets; 0 = disabled (default), minimum 2",
			"server_alive_interval": 30,
			"sftp": {
			  "enable_sftp": true,
			  "sftp_root_directory": "/tmp",
			  "sftp_disable_download": false,
			  "sftp_disable_upload": false
			}
		}
	}
}
```
</details>
<details>
<summary>pam_data.resources.pamMachine (VNC)</summary>

```json
{
	"type": "pamMachine",
	"title": "PAM VNC Machine",
	"notes": "VNC Machine1",
	"host": "127.0.0.1",
	"port": "3389",
	"ssl_verification" : true,
	"operating_system": "Windows",
	"instance_name": "InstanceName",
	"instance_id": "InstanceId",
	"provider_group": "ProviderGroup",
	"provider_region": "us-east1",
	"otp": "otpauth://totp/Example:alice3@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ExampleApp3",
	"attachments": [],
	"scripts": [],
	"pam_settings": {
		"options" : {
			"rotation": "on",
			"connections": "on",
			"tunneling": "on",
			"remote_browser_isolation": "on",
			"graphical_session_recording": "on",
		},
		"allow_supply_host": false,
		"port_forward": {
			"_comment": "Tunneling settings",
			"port": "2222",
			"reuse_port": true
		},
		"connection" : {
			"_comment": "Connections settings per protocol - VNC",
			"protocol": "vnc",
			"port": "2222",
			"allow_supply_user": true,
			"administrative_credentials": "admin1",
			"launch_credentials": "user1",
			"recording_include_keys": true,
			"disable_copy": true,
			"disable_paste": true,
			"destination_host": "127.0.0.2",
			"destination_port": "2121",
			"disable_display_resize": false,
			"_comment_disable_display_resize": "VNC only (disable-display-resize): do not send display resize requests; RDP uses resize_method instead",
			"read_only": false,
			"swap_red_blue": false,
			"force_lossless": false,
			"_comment_cursor": "local (default, rendered by the client) | remote (rendered on the server; the local pointer is shown as a small dot)",
			"cursor": "local",
			"_comment_color_depth": "bits per pixel: 8 | 16 | 24 | 32 (omit to let the server decide)",
			"color_depth": "24",
			"_comment_compress_level": "0 (no compression, fastest) .. 9 (maximum compression); Web Vault presets: 0 None, 3 Low, 6 Balanced, 8 High, 9 Maximum",
			"compress_level": 6,
			"_comment_quality_level": "0 (lowest) .. 9 (best) JPEG quality, used with the tight encoding; Web Vault presets: 0 Low, 3 Medium, 6 High, 9 Best",
			"quality_level": 6,
			"_comment_encodings": "space separated list (a JSON list also works): copyrect hextile raw rre tight zrle (also ultra zlib corre); omit for the default order",
			"encodings": "tight zrle",
			"_comment_clipboard_encoding": "ISO8859-1 (default) | UTF-8 | UTF-16 | CP1252 | MacRoman",
			"clipboard_encoding": "UTF-8",
			"enable_audio": true,
			"audio_servername": "pulse.example.com",
			"sftp": {
			  "enable_sftp": true,
			  "sftp_resource": "Machine2",
			  "sftp_user_credentials": "sftp user2",
			  "sftp_root_directory": "/opt/sftp",
			  "sftp_upload_directory": "/opt/uploads",
			  "sftp_keepalive_interval": 12,
			  "sftp_timeout": 30,
			  "sftp_disable_download": false,
			  "sftp_disable_upload": false
			}
		}
	}
}
```
</details>
<details>
<summary>pam_data.resources.pamMachine (Telnet)</summary>

```json
{
	"type": "pamMachine",
	"title": "PAM Telnet Machine",
	"notes": "Telnet Machine1",
	"host": "127.0.0.1",
	"port": "3389",
	"ssl_verification" : true,
	"operating_system": "Windows",
	"instance_name": "InstanceName",
	"instance_id": "InstanceId",
	"provider_group": "ProviderGroup",
	"provider_region": "us-east1",
	"otp": "otpauth://totp/Example:alice3@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ExampleApp3",
	"attachments": [],
	"scripts": [],
	"pam_settings": {
		"options" : {
			"rotation": "on",
			"connections": "on",
			"tunneling": "on",
			"remote_browser_isolation": "on",
			"graphical_session_recording": "on",
			"text_session_recording": "on"
		},
		"allow_supply_host": false,
		"port_forward": {
			"_comment": "Tunneling settings",
			"port": "2222",
			"reuse_port": true
		},
		"connection" : {
			"_comment": "Connections settings per protocol - RDP",
			"protocol": "telnet",
			"port": "2222",
			"allow_supply_user": true,
			"administrative_credentials": "admin1",
			"launch_credentials": "user1",
			"recording_include_keys": true,
			"disable_copy": true,
			"disable_paste": true,
			"color_scheme": "gray-black",
			"font_size": "18",
			"scrollback": 5000,
			"username_regex": "regex: username",
			"password_regex": "regex: password",
			"login_success_regex": "regex: login success",
			"login_failure_regex": "regex: login failure",
			"font_name": "Menlo",
			"read_only": false,
			"_comment_backspace": "127 = Delete (Ctrl-?, default) | 8 = Backspace (Ctrl-H)",
			"backspace": "127",
			"terminal_type": "xterm-256color"
		}
	}
}
```
</details>
<details>
<summary>pam_data.resources.pamMachine (Kubernetes)</summary>

```json
{
	"type": "pamMachine",
	"title": "PAM K8S Machine",
	"notes": "K8S Machine1",
	"host": "127.0.0.1",
	"port": "3389",
	"ssl_verification" : true,
	"operating_system": "Windows",
	"instance_name": "InstanceName",
	"instance_id": "InstanceId",
	"provider_group": "ProviderGroup",
	"provider_region": "us-east1",
	"otp": "otpauth://totp/Example:alice3@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ExampleApp3",
	"attachments": [],
	"scripts": [],
	"pam_settings": {
		"options" : {
			"rotation": "on",
			"connections": "on",
			"tunneling": "on",
			"remote_browser_isolation": "on",
			"graphical_session_recording": "on",
			"text_session_recording": "on"
		},
		"allow_supply_host": false,
		"port_forward": {
			"_comment": "Tunneling settings",
			"port": "2222",
			"reuse_port": true
		},
		"connection" : {
			"_comment": "Connections settings per protocol - K8S",
			"protocol": "kubernetes",
			"port": "2222",
			"allow_supply_user": true,
			"administrative_credentials": "admin1",
			"launch_credentials": "user1",
			"recording_include_keys": true,
			"color_scheme": "gray-black",
			"font_size": "18",
			"scrollback": 5000,
			"namespace": "namespace",
			"pod_name": "pod name",
			"container": "container name",
			"ignore_server_cert": true,
			"ca_certificate": "cert authority certificate\nline2",
			"client_certificate": "client certificate\nline2\n",
			"client_key": "client key\nline2",
			"use_ssl": true,
			"_comment_exec_command": "command to run in the container; omit for the default shell",
			"exec_command": "/bin/bash",
			"font_name": "Menlo",
			"read_only": false,
			"_comment_backspace": "127 = Delete (Ctrl-?, default) | 8 = Backspace (Ctrl-H)",
			"backspace": "127"
		}
	}
}
```
</details>
<details>
<summary>pam_data.resources.pamDatabase</summary>

```json
{
	"pam_data": {
		"resources": [
			{
				"type": "pamDatabase",
				"title": "PAM MySQL Machine",
				"notes": "DB Machine1",
				"host": "127.0.0.1",
				"port": "13306",
				"use_ssl" : true,
				"database_id": "DatabaseId",
				"database_type": "mysql",
				"_comment": "database types: <postgresql|postgresql-flexible|mysql|mysql-flexible|mariadb|mariadb-flexible|mssql|oracle|mongodb>",
				"provider_group": "ProviderGroup",
				"provider_region": "us-east1",
				"otp": "otpauth://totp/Example:alice3@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ExampleApp3",
				"attachments": [],
				"scripts": [],
				"pam_settings": {
					"options" : {
						"rotation": "on",
						"connections": "on",
						"tunneling": "on",
						"remote_browser_isolation": "on",
						"graphical_session_recording": "on",
						"text_session_recording": "on",
						"ai_threat_detection": "off",
						"ai_terminate_session_on_detection": "off"
					},
					"allow_supply_host": false,
					"port_forward": {
						"port": "2222",
						"reuse_port": true,
						"allow_keeper_db_proxy": true
					},
					"connection" : {
						"protocol": "mysql",
						"_comment": "DB protocol types: <sql-server|postgresql|mysql|mariadb|oracle|mongodb|redis|elasticsearch|clickhouse|dynamodb>",
						"port": "2222",
						"allow_supply_user": true,
						"administrative_credentials": "admin1",
						"launch_credentials": "user1",
						"recording_include_keys": true,
						"disable_copy": true,
						"disable_paste": true,
						"color_scheme": "gray-black",
						"font_size": "18",
						"scrollback": 5000,
						"disable_csv_import": true,
						"disable_csv_export": true,
						"default_database": "db1",
						"font_name": "Menlo",
						"read_only": false,
						"_comment_db_connection_method": "cli | keeperDB | both (omit for cli on mysql / postgresql / sql-server; KeeperDB-only protocols always use keeperDB)",
						"db_connection_method": "both",
						"_comment_session_persistence": "KeeperDB sessions only: none (incognito) | user (profile per user and resource) | resource (profile shared per resource)",
						"session_persistence": "user"
					}
				},
				"users": []
			},
			{
				"type": "pamDatabase",
				"title": "PAM MongoDB Machine",
				"database_type": "mongodb",
				"host": "127.0.0.8",
				"port": "27017",
				"use_ssl": true,
				"users": [{"type": "pamUser","login": "pamuser2","password": "*****"}]
			}
		]
	}
}
```
</details>
<details>
<summary>pam_data.resources.pamDirectory</summary>

```json
{
	"pam_data": {
		"resources": [
			{
				"type": "pamDirectory",
				"title": "PAM Directory Machine",
				"notes": "Directory Machine1",
				"host": "127.0.0.1",
				"port": "3389",
				"use_ssl" : true,
				"domain_name": "MyDomain",
				"alternative_ips": ["127.0.0.1", "127.0.0.2"],
				"directory_id": "DirectoryId",
				"directory_type": "active_directory",
				"user_match": "UserMatch1",
				"provider_group": "ProviderGroup",
				"provider_region": "us-east1",
				"otp": "otpauth://totp/Example:alice3@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ExampleApp3",
				"attachments": [],
				"scripts": [],
				"pam_settings": {
					"options" : {
						"rotation": "on",
						"connections": "on",
						"tunneling": "on",
						"remote_browser_isolation": "on",
						"graphical_session_recording": "on",
						"text_session_recording": "on"
					},
					"allow_supply_host": false,
					"port_forward": {
						"port": "2222",
						"reuse_port": true
					},
					"connection" : {
						"_comment": "Connections settings per protocol - RDP",
						"protocol": "ssh",
						"port": "2222",
						"allow_supply_user": true,
						"administrative_credentials": "admin1",
						"launch_credentials": "user1",
						"recording_include_keys": true,
						"disable_copy": true,
						"disable_paste": true,
						"color_scheme": "gray-black",
						"font_size": "18",
						"scrollback": 5000,
						"public_host_key": "<Public Host Key (Base64)>",
						"command": "/bin/bash",
						"sftp": {
							"enable_sftp": true,
							"sftp_root_directory": "/tmp"
						}
					}
				},
				"users": []
			},
			{
				"type": "pamDirectory",
				"directory_type": "openldap",
				"host": "127.0.0.8",
				"port": "636",
				"use_ssl": true,
				"users": [{"type": "pamUser","login": "pamuser2","password": "*****"}]
			}
		]
	}
}
```
</details>
<details>
<summary>pam_data.resources.pamRemoteBrowser</summary>

```json
{
	"pam_data": {
		"resources": [
			{
				"type": "pamRemoteBrowser",
				"title": "RBI Hotmail",
				"notes": "PAM RBI User",
				"url": "https://bing.com",
				"otp": "otpauth://totp/Example:alice3@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ExampleApp3",
				"attachments": [],
				"pam_settings": {
					"options" : {
						"remote_browser_isolation": "on",
						"graphical_session_recording": "on"
					},
					"connection" : {
						"protocol": "http",
						"_comment": "RBI runs only on 'http' protocol",
						"recording_include_keys": true,
						"disable_copy": true,
						"disable_paste": true,
						"clipboard_buffer_size": "10mb",
						"_comment_clipboard_buffer_size": "default | 256kb | 1mb | 10mb | 50mb (case-insensitive); default or omitted = unset",
						"allow_supply_user": true,
						"autofill_credentials": "rbi_hotmail_user1",
						"allow_url_manipulation": true,
						"allowed_url_patterns": "*.com\n*.org",
						"allowed_resource_url_patterns": "*.org\n*.gov",
						"autofill_targets": "autofil_target1\nautofil_target2",
						"ignore_server_cert": true,
						"session_persistence": "none",
						"_comment_session_persistence": "none | user | resource",
						"allow_file_uploads": true,
						"allow_file_downloads": true,
						"accept_language": "en-US,en;q=0.9",
						"suppress_js_dialogs": true,
						"disable_audio": false,
						"audio_channels": 2,
						"_comment_audio_channels": "1 (mono) or 2 (stereo)",
						"audio_bps": 16,
						"_comment_audio_bps": "8 or 16",
						"audio_sample_rate": 44100
					}
				}
			},
			{
				"type": "pamRemoteBrowser",
				"title": "website1",
				"url": "https://127.0.0.1",
				"pam_settings": {
					"options" : { "remote_browser_isolation": "on" },
					"connection" : { "protocol": "http" }
				}
			}
		]
	}
}
```
</details>

- **Users** are defiend in `pam_data.users` - users that do not belong to a single machine are defined in `pam_data.users` These are records type: `login` or `pamUser` for NOOP rotation or shared across multiple machines _(ex. same user for ssh, vnc, rdp etc.)_
<details>
<summary>pam_data.users.login</summary>

```json
{
	"pam_data": {
		"users": [
			{
				"type": "login",
				"title": "rbi_hotmail_user1",
				"login": "user1@hotmail.com",
				"password": "*****",
				"otp": "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ExampleApp"
			}
		]
	}
}
```
</details>
<details>
<summary>pam_data.users.pamUser</summary>

```json
{
	"pam_data": {
		"users": [
			{
				"type": "pamUser",
				"title": "PAM User1 - general rotation",
				"notes": "PAM User1 Notes",
				"login": "pamuser1",
				"password": "*****",
				"private_pem_key": "-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----",
				"distinguished_name": "User1 Distinguished Name",
				"connect_database": "user1_connect_db1",
				"managed" : true,
				"otp": "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ExampleApp",
				"attachments": ["/path/to/file1.txt", "/path/to/file.xls"],
				"scripts": [{"script_command": "pwsh.exe","file": "/path/to/script1.ps1","additional_credentials": ["admin2"]}],
				"rotation_settings": {
					"rotation": "general",
					"enabled": "on",
					"schedule": {"type": "on-demand"},
					"password_complexity": "32,5,5,5,5"
				}
			},
			{
				"type": "pamUser",
				"title": "PAM User2 - iam_user rotation",
				"login": "pamuser2",
				"password": "*****",
				"rotation_settings": {
					"rotation": "iam_user",
					"enabled": "on",
					"schedule": {"type": "CRON", "cron": "30 18 * * *" },
					"password_complexity": "32,5,5,5,5"
				}
			},
			{
				"type": "pamUser",
				"title": "PAM User3 - scripts_only rotation (NOOP)",
				"login": "pamuser3",
				"password": "*****",
				"rotation_settings": {
					"rotation": "scripts_only",
					"enabled": "on",
					"schedule": {"type": "on-demand"},
					"password_complexity": "32,5,5,5,5"
				}
			}
		]
	}
}
```
</details>
