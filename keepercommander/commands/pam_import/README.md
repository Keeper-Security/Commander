## PAM Import Command
PAM Import command helps customers with thousands of managed companies to automate the creation of folders, gateways, machines, users, connections, tunnels and (optionally) rotations.

### Command line options

`pam project import --name=project1 --filename=/path/to/import.json --dry-run`

- `--name`, `-n` → Project name _(overrides `"project":""` from JSON)_
- `--filename`, `-f` → JSON file to load import data from.
- `--dry-run`, `-d` → Test import without modifying vault.


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
Each Machine (pamMachine, pamDatabase, pamDirectory) can specify admin user which will be identified by its unique title or login/username (ex. `"admin_credentials": "admin1"`, or `pamRemoteBrowser` → `pam_settings.connection.autofill_credentials: "BingLogin"`)
- **Machines** are defined in `pam_data.resources` where each machine can have its own list of `"users": []` one of which is the admin user for that machine. Users that don't belong to a single machine are into global `pam_data.users` section (record type: `login`, `pamUser` for NOOP rotation or shared across multiple machines /ex. same user for ssh, vnc, rdp etc./)
  > **Note 1:** `pam_settings` _(options, connection)_ are explained only in pamMachine section below (per protocol) but they are present in all machine types.  
  > **Note 2:** `attachments` and `scripts` examples are in `pam_configuration: local` section.  
  > **Note 3:** Post rotation scripts (a.k.a. `scripts`) are executed in following order: `pamUser` scripts after any **successful** rotation for that user, `pamMachine` scripts after any **successful** rotation on the machine and `pamConfiguration` scripts after any rotation using that configuration.
<details>
<summary>pam_data.resources.pamMachine (RDP)</summary>

```json
{
    "type": "pamMachine",
    "title": "PAM RDP Machine",
    "notes": "RDP Machine1",
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
            "_comment": "Connections settings per protocol - RDP",
            "protocol": "rdp",
            "port": "2222",
            "allow_supply_user": true,
            "administrative_credentials": "admin1",
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
			"text_session_recording": "on"
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
						"text_session_recording": "on"
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
