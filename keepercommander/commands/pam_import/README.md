## PAM Project Import Commands
PAM Import command helps customers with thousands of managed companies to automate the creation of folders, gateways, machines, users, connections, tunnels and (optionally) rotations.

### Command line options

Initial Import.  
`pam project import --name=project1 --filename=/path/to/import.json [--dry-run]`

- `--name`, `-n` → Project name _(overrides `"project":""` from JSON)_
- `--filename`, `-f` → JSON file to load import data from.
- `--dry-run`, `-d` → Test import without modifying vault.


Adding new PAM resources and users to an existing PAM configuration from an import file. The command validates folders and records, then creates only new items (match by title, existing records are skipped). The import JSON format is the same.  
`pam project extend --config=<uid_or_title> --filename=/path/to/import.json [--dry-run]`

- `--config`, `-c` → PAM Configuration record UID or title.
- `--filename`, `-f` → JSON file to load import data from.
- `--dry-run`, `-d` → Test import without modifying vault.

> **Notes:**
- Use **`--dry-run`** to preview what would be created and to see detailed validation output without changing the vault.
- If the command reports errors, run it again with **`--dry-run`** for more detailed error messages.


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
  > **Note 4:** When `allow_supply_user` is false and JIT ephemeral is not used, vault may require a launch credential; import can provide it via `launch_credentials` in the resource's `connection` block.

JIT and KeeperAI settings below are shared across all resource types (pamMachine, pamDatabase, pamDirectory) except User and RBI (pamRemoteBrowser) records.

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
            "ai_settings": {}
        },
        "allow_supply_host": false,
        "port_forward": {
            "_comment": "Tunneling settings",
            "_comment_port": "remote tunneling port",
            "port": "2222",
            "reuse_port": true
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
                "sftp_keepalive_interval": 12
            },
            "disable_audio": true,
            "disable_dynamic_resizing": false,
            "enable_full_window_drag": true,
            "enable_wallpaper": true
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
			"reuse_port": true
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
			"public_host_key": "<Public Host Key (Base64)>",
			"command": "/bin/bash",
			"sftp": {
			  "enable_sftp": true,
			  "sftp_root_directory": "/tmp"
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
			"sftp": {
			  "enable_sftp": true,
			  "sftp_resource": "Machine2",
			  "sftp_user_credentials": "sftp user2",
			  "sftp_root_directory": "/opt/sftp",
			  "sftp_upload_directory": "/opt/uploads",
			  "sftp_keepalive_interval": 12
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
			"username_regex": "regex: username",
			"password_regex": "regex: password",
			"login_success_regex": "regex: login success",
			"login_failure_regex": "regex: login failure"
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
			"namespace": "namespace",
			"pod_name": "pod name",
			"container": "container name",
			"ignore_server_cert": true,
			"ca_certificate": "cert authority certificate\nline2",
			"client_certificate": "client certificate\nline2\n",
			"client_key": "client key\nline2"
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
						"reuse_port": true
					},
					"connection" : {
						"protocol": "mysql",
						"_comment": "protocol types: <sql-server|postgresql|mysql>",
						"port": "2222",
						"allow_supply_user": true,
						"administrative_credentials": "admin1",
						"launch_credentials": "user1",
						"recording_include_keys": true,
						"disable_copy": true,
						"disable_paste": true,
						"disable_csv_import": true,
						"disable_csv_export": true,
						"default_database": "db1"
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
				"users": [{"type": "pamUser","login": "pamuser2","password": "p4mus3r2!"}]
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
				"users": [{"type": "pamUser","login": "pamuser2","password": "p4mus3r2!"}]
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
						"autofill_credentials": "rbi_hotmail_user1",
						"allow_url_manipulation": true,
						"allowed_url_patterns": "*.com\n*.org",
						"allowed_resource_url_patterns": "*.org\n*.gov",
						"autofill_targets": "autofil_target1\nautofil_target2",
						"ignore_server_cert": true
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
				"password": "User1Pa$$w0rd!",
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
				"password": "pamuser1Pa$$w0rd!",
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
				"password": "pamuser2Pa$$w0rd!",
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
				"password": "pamuser3Pa$$w0rd!",
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

---

## KCM Import (`pam project kcm-import`)

Import connections from a KCM (Keeper Connection Manager / Apache Guacamole) database directly into Keeper Vault as PAM records. Supports Docker auto-detection, multiple folder hierarchy modes, group filtering, and depth limiting.

### Quick Start

```bash
# Docker auto-detect (most common)
pam project kcm-import --docker-detect --docker-container guacamole-1 \
  --db-type postgresql --name "My KCM Project"

# Manual database connection
pam project kcm-import --db-host 10.0.0.5 --db-type postgresql \
  --db-ssl --name "My KCM Project"

# Preview what will be imported (no vault changes)
pam project kcm-import --docker-detect --docker-container guacamole-1 \
  --db-type postgresql --preview-groups --folder-mode exact --strip-root

# Export to JSON for review before importing
pam project kcm-import --docker-detect --docker-container guacamole-1 \
  --db-type postgresql --folder-mode qualified \
  --output /tmp/kcm-export.json --name "My KCM Project"
```

### Command Line Options

#### Database Connection
| Flag | Description | Default |
|------|-------------|---------|
| `--db-host` | KCM database hostname | _(required unless --docker-detect)_ |
| `--db-type` | Database type: `mysql` or `postgresql` | `mysql` |
| `--db-port` | Database port | 3306 (mysql) / 5432 (postgresql) |
| `--db-name` | Database name | `guacamole_db` |
| `--db-user` | Database username | `guacamole_user` |
| `--db-password-record` | Vault record UID containing DB password | _(prompts if not set)_ |
| `--db-ssl` | Require SSL/TLS for database connection | `false` |
| `--allow-cleartext` | Allow unencrypted remote connection | `false` |
| `--docker-detect` | Auto-detect credentials from Docker container | `false` |
| `--docker-container` | Docker container name for auto-detect | `guacamole` |

#### Folder Hierarchy (Tested & Verified)
| Flag | Description | Default |
|------|-------------|---------|
| `--folder-mode` | Group mapping mode (see below) | `ksm` |
| `--strip-root` | Remove `ROOT/` prefix (use with `exact` mode) | `false` |
| `--group-depth` | Max folder nesting depth (0=unlimited) | `0` |

**Folder modes:**
- **`ksm`** — Uses KSM config attributes on groups as folder anchors. Groups without `ksm-config` attributes are flattened into their nearest configured ancestor. Best for KSM-managed hierarchies.
- **`exact`** — Full path hierarchy: `ROOT/Parent/Child/Grandchild`. Mirrors the exact KCM group tree. Combine with `--strip-root` to remove the `ROOT/` prefix.
- **`flat`** — All groups become top-level folders. Simple but may collide if sibling groups under different parents share names.
- **`qualified`** — Parent-qualified flat names: `"Parent - Child"`. Avoids collisions without deep nesting. Auto-qualifies further (grandparent prefix or numeric suffix) if collisions persist.

#### Group Filtering (Tested & Verified)
| Flag | Description | Default |
|------|-------------|---------|
| `--exclude-groups` | Comma-separated group names or IDs to exclude | _(none)_ |
| `--preview-groups` | Show group-to-folder mapping tree and exit | `false` |

`--exclude-groups` cascades to descendants: excluding a parent group automatically excludes all its child groups and their connections. Warns if any specified names/IDs don't match existing groups.

#### Import Options
| Flag | Description | Default |
|------|-------------|---------|
| `--name`, `-n` | Project name | `KCM-Import-<timestamp>` |
| `--config`, `-c` | Existing PAM config UID (extend mode) | _(creates new)_ |
| `--output`, `-o` | Save JSON to file instead of importing | _(imports to vault)_ |
| `--gateway`, `-g` | Existing gateway UID or name | _(creates new)_ |
| `--max-instances` | Gateway pool size (0=skip) | `0` |
| `--dry-run`, `-d` | Preview without vault changes | `false` |
| `--skip-users` | Import resources only, skip user records | `false` |
| `--include-disabled` | Include disabled KCM connections | `false` |

### E2E Tested Scenarios

All scenarios below were tested against a live KCM (Keeper Connection Manager) PostgreSQL database with 216 connections across 42 connection groups, importing into a production Keeper Vault. All commands are full working examples.

#### 1. Preview Group-to-Folder Mapping (all modes)

Preview the folder structure before importing — no vault changes are made.

```bash
# Preview with each folder mode
keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --preview-groups --folder-mode ksm

keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --preview-groups --folder-mode exact --strip-root

keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --preview-groups --folder-mode flat

keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --preview-groups --folder-mode qualified
```

#### 2. Full Import — Exact Mode with Strip Root (Tested & Verified: 290 resources, 290 users)

The recommended mode for preserving the full KCM group hierarchy without the `ROOT/` prefix.

```bash
keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --folder-mode exact --strip-root \
  --name "KCM-Full-Import"
```

#### 3. Export to JSON — Qualified Mode (Tested & Verified: 290 resources, 290 users)

Export to JSON for manual review or later import via `pam project extend`.

```bash
keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --folder-mode qualified \
  --output /tmp/kcm-qualified.json --name "KCM-Qualified"

# Verify exported JSON
python3 -c "
import json
d = json.load(open('/tmp/kcm-qualified.json'))
print(f'Resources: {len(d[\"pam_data\"][\"resources\"])}')
print(f'Users: {len(d[\"pam_data\"][\"users\"])}')
paths = sorted(set(r['folder_path'] for r in d['pam_data']['resources']))
for p in paths: print(f'  {p}')
"
```

#### 4. Exclude Specific Groups (Tested & Verified: 42→40 groups, 216→184 connections)

Exclude groups by name or ID. Cascades to all child groups.

```bash
keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --preview-groups --folder-mode qualified \
  --exclude-groups "Your Linux Boxes,Your Windows Boxes"
```

#### 5. Depth-Limited Import (Tested & Verified)

Collapse groups deeper than N levels into their nearest ancestor folder.

```bash
# Preview depth-limited hierarchy (max 2 levels)
keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --preview-groups --folder-mode exact --strip-root --group-depth 2
```

#### 6. Dry Run — Preview Records (Tested & Verified)

Show what would be imported with credentials redacted.

```bash
keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --folder-mode exact --strip-root --dry-run \
  --name "DryRunTest"
```

#### 7. Extend Existing PAM Configuration (Tested & Verified)

Add new connections to an existing PAM environment without creating new infrastructure.

```bash
# First export the new connections
keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --folder-mode exact --strip-root \
  --output /tmp/kcm-extend.json --name "ExistingProject"

# Then extend
keeper pam project extend \
  --config "<existing-pam-config-uid>" \
  --filename /tmp/kcm-extend.json
```

#### 8. Reuse Existing Gateway (Tested & Verified)

Import into an existing PAM environment using an already-deployed gateway. Skips gateway creation entirely.

```bash
# Use existing gateway by name
keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --folder-mode qualified \
  --gateway "The Lab Gateway" \
  --output /tmp/gw-reuse.json --name "GW-Reuse-Test"

# Or by gateway UID
keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --folder-mode exact --strip-root \
  --gateway "SBs-l-KdS7CbHN18MzCxQQ" \
  --name "GW-By-UID"
```

#### 9. Auto-Deploy Gateway via Docker

Automatically deploy the gateway as a Docker container after import. The command captures the access token from Phase 1 and runs `docker run` for you.

```bash
keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --folder-mode exact --strip-root \
  --deploy-gateway --gateway-name "kcm-gateway" \
  --name "Auto-Deploy-Test"

# With custom image
keeper pam project kcm-import \
  --docker-detect --docker-container kcm-setup-guacamole-1 \
  --db-type postgresql --db-host 192.168.64.5 --allow-cleartext \
  --folder-mode exact --strip-root \
  --deploy-gateway --gateway-name "my-gw" \
  --gateway-image "keeper/gateway:1.8.0" \
  --name "Custom-Image-Deploy"
```

#### 10. Import with SSL and Password from Vault Record

Secure production import using SSL and password stored in a Keeper record.

```bash
keeper pam project kcm-import \
  --db-host kcm-db.example.com --db-type postgresql --db-ssl \
  --db-password-record "<vault-record-uid>" \
  --folder-mode qualified --name "Production-KCM"
```

### Gateway Options

| Flag | Description | Default |
|------|-------------|---------|
| `--gateway`, `-g` | Existing gateway UID or name (skips creation) | _(creates new)_ |
| `--deploy-gateway` | Auto-deploy gateway via Docker after creation | `false` |
| `--gateway-name` | Docker container name for auto-deploy | `keeper-gateway` |
| `--gateway-image` | Docker image for auto-deploy | `keeper/gateway:latest` |
| `--max-instances` | Gateway pool size (HA, 0=skip) | `0` |

**Gateway flow:**
- **No `--gateway` flag** (default): Phase 1 creates a new gateway + KSM app. Access token is captured and shown in deployment instructions. Use `--deploy-gateway` to auto-run `docker run`.
- **`--gateway <name/uid>`**: Finds the existing gateway, resolves its PAM config, and imports directly via extend mode. No new gateway or KSM app is created.
- **`--config <uid>`**: Extend mode — adds records to an existing PAM configuration. No gateway creation.

### What Gets Imported

Each KCM connection produces:
- **1 Resource record** (`pamMachine`, `pamDatabase`, or `pamRemoteBrowser`) with full connection settings
- **1 User record** (`pamUser`) with credentials and TOTP (if configured)
- **1 SFTP sub-resource + 1 SFTP user** (for SSH connections with SFTP enabled)

**Parameter migration** from KCM/Guacamole:
- 33 parameters actively mapped (recording settings, security, SFTP, UI options, etc.)
- 19 parameters dropped (Guacamole-specific with no Keeper equivalent)
- 4 parameters ignored (internal KCM state)
- Protocol mapping: `ssh`, `rdp`, `vnc`, `telnet`, `kubernetes` -> `pamMachine`; `http` -> `pamRemoteBrowser`; `mysql`, `postgres`, `sql-server` -> `pamDatabase`

### Two-Phase Import Architecture

1. **Phase 1 (Infrastructure):** Creates shared folders (`<Project> - Resources`, `<Project> - Users`), KSM application, gateway, and PAM configuration via `pam project import`
2. **Phase 2 (Records):** Imports all resource and user records into the correct subfolders via `pam project extend`

### Import Statistics

The command displays timing and throughput statistics after import completion:
- Total elapsed time
- Records per second throughput
- Average time per record

### Security Notes

- Database passwords are cleared from memory after use (best effort)
- Docker environment variables are cleared after credential extraction via `try/finally`
- Output JSON files are created with `0600` permissions and a warning about plaintext credentials
- Connection names are sanitized (null bytes, control characters stripped)
- Folder paths are sanitized against traversal attacks (`/`, `\`, `..` replaced; length-limited to 200 chars)
- Remote database connections require `--db-ssl` or explicit `--allow-cleartext`
- The `--dry-run` mode redacts passwords, private keys, and TOTP secrets
- PAM config lookup uses exact title match to prevent ambiguous matches
- Cycle detection in group tree traversal prevents infinite loops from malformed data
