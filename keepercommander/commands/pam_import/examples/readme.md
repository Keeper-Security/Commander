# Bulk‑Importing RDP Resources with Keeper Commander

This guide explains how to convert a simple CSV list of Windows hosts into a **PAM Project** import file that Keeper Commander can ingest.  Use it when onboarding large numbers of RDP servers.

---

## Overview of the Workflow

1. **Prepare a CSV** that contains the target servers and credentials.
2. **Create or edit a JSON template** that describes the project, policies and directory binding.
3. **Run the helper script** to merge the CSV data with the template and produce `pam_import.json`.
4. **Import the file** with the `pam project import` command.

---

## Prerequisites

| Requirement                               | Notes                           |
| ----------------------------------------- | ------------------------------- |
| Keeper Commander v17.1.1 or later           | Verify with `keeper version`    |
| Python 3.8+                               | Required to execute the script  |
| Keeper PAM module                         | Enabled in the vault & licensed |
| Admin role with **Manage PAM** permission | Needed to import projects       |

---

## 1 – Prepare the CSV

The script expects a comma‑separated file named `servers_to_import.csv` by default.  Each row must contain exactly three fields:

```csv
hostname,username,password
srv‑01,Administrator,P@55w0rd!
srv‑02,Administrator,P@55w0rd!
```

> **Tip:** The first line is treated as a header if it matches the column names above.

---

## 2 – Create the JSON Template

The template defines the **PAM Project**, directory binding ( **`pamDirectory`** ), and a single **`pamMachine`** entry that the script will use as a clone‑able blueprint.

1. Save the [sample template](#appendix-sample-template) as `import_template.json`.
2. Replace every value beginning with `XXX:` with an actual value.
3. Leave placeholders beginning with `xxx:` untouched—these are overwritten by the script.

#### Template Validation Checklist

During execution the script validates the template **before** touching any data. If any rule below fails it exits with a clear message and a non‑zero status:

| Requirement                                                    | Detail                                                                                                                                                                 |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pam_configuration.environment`                                | Must be `local`. Other values abort the run.                                                                                                                           |
| `pam_configuration.connections` & `pam_configuration.rotation` | Must be `"on"`. The script will switch them on automatically and print a warning if they are not.                                                                      |
| `pam_data.resources`                                           | Must contain **exactly two** objects **in this order**: (1) a `pamDirectory` and (2) a `pamMachine`.                                                                   |
| `pamDirectory` & `pamMachine`                                  | Each must hold at least one `pamUser` child object.                                                                                                                    |
| Administrative credentials                                     | Both objects must include `pam_settings.connection.administrative_credentials`. The value in `pamMachine` must reference the directory‑level admin user title exactly. |
| Placeholders                                                   | Any remaining values beginning with `XXX:` stop execution until replaced.                                                                                              |

> The script validates the template before processing.  Any missing values or structural problems will result in an explanatory error.

---

## 3 – Generate the Import File

```bash
python3 import_rdp_servers.py --input-file servers_to_import.csv  --template-file import_template.json --output-file pam_import.json
```

| Option            | Default    | Description                                                                                   |
| ----------------- | ---------- | --------------------------------------------------------------------------------------------- |
| `--prefix-names`  | *disabled* | Prepends the hostname to the username when creating PAM user titles (`srv‑01‑Administrator`). |
| `--show-template` | –          | Prints the built‑in sample template and exits.                                                |

The script reports the number of processed rows and any skipped duplicates or incomplete entries.

---

## 4 – Import into Keeper PAM

```bash
keeper pam project import -f pam_import.json
```

* Commander summarizes the proposed changes and prompts for confirmation before writing records to the vault.
* If the import is successful, each server appears as a **PAM Machine** under the specified project, with RDP connectivity and rotation enabled.

---

## Understanding User Records

### Directory Administrative User (`pamDirectory` → `pamUser`)

* **Title** – must exactly match the value referenced in the `pam_settings.connection.administrative_credentials` field. A mismatch here will break rotation and connections.
* **Login** – the UPN or DN of the account that has rights to reset Windows passwords and enable RDP.
* **Password** – required for the initial import. **Rotate or delete it immediately after onboarding.**
* **Rotation Settings** – defaults to **on‑demand**; adjust in the template if you need a schedule.

### Machine User (`pamMachine` → `pamUser`)

* **Title** – by default the same as the server’s hostname; add the `--prefix-names` flag to create `hostname‑username` titles for easier searching.
* **Login** – the account that will log in to the Windows host over RDP.
* **Password** – pulled directly from the CSV row.
* **Rotation Settings** – inherits the same default; override in the template if you need host‑specific rules.

**Key Points**

* One CSV row ⇒ one `pamMachine` + one `pamUser`.
* Duplicate hostnames are skipped to prevent accidental collisions.
* To onboard multiple accounts per server, add additional rows for the same hostname (using different usernames) or extend the generated JSON manually.

---

## Troubleshooting

| Symptom                                               | Likely Cause                                                               | Resolution                                                                |
| ----------------------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `JSON template file not found`                        | Incorrect `--template-file` path                                           | Provide the correct path or use `--show-template` to generate a new file. |
| `Duplicate hostname <host> – skipped`                 | Same server listed more than once                                          | Remove duplicates from the CSV.                                           |
| `Template still missing required values`              | One or more `XXX:` placeholders unchanged                                  | Replace all `XXX:` values with actual data.                               |
| Import reports `administrative_credentials not found` | The `pamDirectory` user title does not match the reference in `pamMachine` | Ensure the title and reference are identical, including case.             |

---

## Appendix – Sample Template

Expand the section below for a fully annotated example.

<details>
<summary>Click to view</summary>

```json
{
    "project": "Project1",
    "shared_folder_users": {
        "manage_users": true,
        "manage_records": true,
        "can_edit": true,
        "can_share": true
    },
    "shared_folder_resources": {
        "manage_users": true,
        "manage_records": true,
        "can_edit": true,
        "can_share": true
    },
    "pam_configuration": {
        "environment": "local",
        "connections": "on",
        "rotation": "on",
        "graphical_session_recording": "on"
    },
    "pam_data": {
        "resources": [
            {
                "_comment1": "Every key that starts with '_' is a comment and can be ignored or deleted",
                "_comment2": "Every value that starts with uppercase 'XXX:' must be replaced with actual value (removed if not required)",
                "_comment3": "Every value that starts with lowercase 'xxx:' is just a placeholder - can be replaced with anything but must be present",
                "type": "pamDirectory",
                "title": "XXX:Project1 AD",
                "directory_type": "XXX:active_directory|ldap",
                "host": "XXX:demo.local",
                "port": "XXX:636",
                "use_ssl": true,
                "domain_name": "XXX:demo.local",
                "pam_settings": {
                    "options": {
                        "rotation": "on",
                        "connections": "on",
                        "tunneling": "on",
                        "graphical_session_recording": "on"
                    },
                    "connection": {
                        "protocol": "rdp",
                        "port": "XXX:3389",
                        "security": "XXX:any",
                        "ignore_server_cert": true,
                        "_comment_administrative_credentials": "Must match the unique title of one of the users below",
                        "administrative_credentials": "XXX:DomainAdmin"
                    }
                },
                "users": [
                    {
                        "type": "pamUser",
                        "_comment_title": "Must match administrative_credentials above if this is the admin user",
                        "title": "XXX:DomainAdmin",
                        "_comment_login_password": "Must provide valid credentials but delete sensitive data/json after import",
                        "login": "XXX:administrator@demo.local",
                        "password": "XXX:P4ssw0rd_123",
                        "rotation_settings": {
                            "rotation": "general",
                            "enabled": "on",
                            "schedule": {
                                "type": "on-demand"
                            }
                        }
                    }
                ]
            },
            {
                "_comment4": "While pamDirectory section above is static, the pamMachine section below is dynamicly generated",
                "_comment5": "One pamMachine with one pamUser will be generated per each line from the CSV file",
                "_comment6": "Only one pamMachine is needed and it will be used as a template for all CSV rows",
                "_comment7": "Please do NOT edit lines with xxx: in them - these are placeholders",
                "_comment8": "Any other line that don't contain xxx: can be altered/added/deleted in the template",
                "_comment9": "CSV Format: server_name,username,password",
                "type": "pamMachine",
                "_comment_title_and_host": "server value from CSV",
                "title": "xxx:server1",
                "host": "xxx:server1",
                "port": "5986",
                "ssl_verification": true,
                "operating_system": "Windows",
                "pam_settings": {
                    "options": {
                        "rotation": "on",
                        "connections": "on",
                        "tunneling": "on",
                        "graphical_session_recording": "on"
                    },
                    "connection": {
                        "protocol": "rdp",
                        "port": "3389",
                        "security": "any",
                        "ignore_server_cert": true,
                        "_comment_administrative_credentials": "Format: pamDirectory#title.pamDirectory#administrative_credentials - exact match needed",
                        "administrative_credentials": "XXX:Project1 AD.DomainAdmin"
                    }
                },
                "users": [
                    {
                        "type": "pamUser",
                        "_comment_title": "username value from CSV or server-username if --prefix-names option is used",
                        "title": "xxx:admin",
                        "_comment_login": "username value from CSV",
                        "login": "xxx:Administrator",
                        "_comment_password": "password value from CSV",
                        "password": "xxx:P4ssw0rd_123",
                        "rotation_settings": {
                            "rotation": "general",
                            "enabled": "on",
                            "schedule": {
                                "type": "on-demand"
                            }
                        }
                    }
                ]
            }
        ]
    }
}
```

</details>

---

### Related Topics

* [Keeper Commander – PAM Commands](https://docs.keeper.io/en/keeperpam/commander-cli/command-reference/keeperpam-commands)
* [Managing PAM Projects](https://docs.keeper.io/en/keeperpam/commander-cli/command-reference/keeperpam-commands#sub-command-project)
