# Keeper Commander Service Mode

The Service Mode module for Keeper Commander enables REST API integration by providing a secure, configurable API server that can be deployed with minimal setup. This module allows users to execute Commander CLI commands through a REST API interface while maintaining security and configuration flexibility.

## Features

### Core Functionality
- **API Server**: Flask-based REST API server for executing Commander CLI commands
- **Service Management**: Complete lifecycle management for the API service
- **Configuration Management**: Flexible configuration system with both interactive and streamlined setup options
- **Security Controls**: Comprehensive security features including API key management and access controls

### Service Commands
| Command | Description |
|---------|-------------|
| `service-create` | Initialize and configure the service with customizable settings |
| `service-start` | Start the service with existing configuration |
| `service-stop` | Gracefully stop the running service |
| `service-status` | Display current service status |
| `service-config-add` | Add new API configuration and command access settings |

### Security Features
- API key authentication
- Configurable token expiration (minutes/hours/days)
- Optional AES-256 (CBC) encryption for API responses
- Rate limiting
- IP deny list management
- Request validation and policy enforcement

### Configuration

Create and configure the service with interactive prompts:
```bash
My Vault> service-create
```

You'll be prompted to configure:
- Port number
- Ngrok tunneling (y/n)
  - Ngrok auth token
  - Ngrok custom domain
- Cloudflare tunneling (y/n) - *if ngrok is disabled*
  - Cloudflare tunnel token (required)
  - Cloudflare custom domain (required)
- Enable TLS Certificate (y/n) - *if both ngrok and cloudflare are disabled*
  - TLS Certificate path 
  - TLS Certificate password
- Enable Request Queue (y/n)
- Advanced Security (y/n)
  - Rate Limit
  - Allowed IP List (comma-separated)
  - Denied IP List (comma-separated)
  - Enable Encryption (y/n) 
- List of supported commands (comma separated)
- Run mode (foreground/background)
- Token Expiration Time (Xm, Xh, Xd) or empty for no expiration
- File format (yaml/json)

### Streamlined Configuration

Configure the service streamlined with TLS:

```bash
  My Vault> service-create -p <port> -f <json-or-yaml> -c 'tree,ls,search,record-add,mkdir' -rm <foreground-or-background> -q <y-or-n> -crtf <certificate-file-path> -crtp <certificate-password-key-path> -aip <allowed-ip-list> -dip <denied-ip-list>
```

Configure the service streamlined with Ngrok:

```bash
  My Vault> service-create -p <port> -f <json-or-yaml> -c 'tree,record-add,audit-report' -ng <ngrok-token> -cd <ngrok_custom_domain> -rm <foreground-or-background> -q <y-or-n> -aip <allowed-ip-list> -dip <denied-ip-list>
```

Configure the service streamlined with Cloudflare:

```bash
  My Vault> service-create -p <port> -f <json-or-yaml> -c 'tree,record-add,audit-report' -cf <cloudflare-tunnel-token> -cfd <cloudflare-custom-domain> -rm <foreground-or-background> -q <y-or-n> -aip <allowed-ip-list> -dip <denied-ip-list>
``` 

Parameters:
- `-p, --port`: Port number for the service
- `-c, --commands`: Comma-separated list of allowed commands
- `-ng, --ngrok`: Ngrok authentication token for public URL access
- `-cd, --ngrok_custom_domain`: Ngrok custom domain name
- `-cf, --cloudflare`: Cloudflare tunnel token (required when using cloudflare)
- `-cfd, --cloudflare_custom_domain`: Cloudflare custom domain name (required when using cloudflare)
- `-f, --fileformat`: File format (json/yaml)
- `-crtf, --certfile`: Certificate file path
- `-crtp, --certpassword`: Certificate password
- `-rm, --run_mode`: Run mode (foreground/background)
- `-q, --queue_enabled`: Enable request queue (y/n)
- `-dip, --deniedip`: Denied IP list to access service
- `-aip, --allowedip`: Allowed IP list to access service

### Service Management

Check service status:
```bash
My Vault> service-status
```

Add additional configuration:
```bash
My Vault> service-config-add
```

Stop the service:
```bash
My Vault> service-stop
```

## API Usage

### API Versioning

The service provides two API versions based on queue configuration:
- **`/api/v2/`** - Queue enabled (default): Asynchronous request processing with enhanced features
- **`/api/v1/`** - Queue disabled (legacy): Direct synchronous execution 

### Request Queue System

The service uses an asynchronous request queue system that provides:
- **Sequential Processing**: Requests are processed one at a time in FIFO order
- **Request Tracking**: Each request receives a unique ID for status tracking
- **No Dropped Requests**: All requests are queued and processed
- **Result Retrieval**: Asynchronous result retrieval using request IDs

#### API Endpoints

**Submit Request:**
```bash
curl -X POST 'http://localhost:<port>/api/v2/executecommand-async' \
--header 'Content-Type: application/json' \
--header 'api-key: <your-api-key>' \
--data '{"command": "tree"}'
```
*Response (202 Accepted):*
```json
{
    "success": true,
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "queued",
    "message": "Request queued successfully. Use /api/v2/status/<request_id> to check progress, /api/v2/result/<request_id> to get results, or /api/v2/queue/status for queue info."
}
```

**Check Request Status:**
```bash
curl 'http://localhost:<port>/api/v2/status/<request_id>' \
--header 'api-key: <your-api-key>'
```
*Response:*
```json
{
    "success": true,
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "command": "tree", 
    "status": "completed",
    "created_at": "2024-01-15T10:30:00.000000",
    "started_at": "2024-01-15T10:30:01.000000",
    "completed_at": "2024-01-15T10:30:03.000000"
}
```

**Get Request Result:**
```bash
curl 'http://localhost:<port>/api/v2/result/<request_id>' \
--header 'api-key: <your-api-key>'
```
*Response (for completed request):*
```json
{
    "result": "...",
    "status": "success"
}
```

**Get Queue Status:**
```bash
curl 'http://localhost:<port>/api/v2/queue/status' \
--header 'api-key: <your-api-key>'
```
*Response:*
```json
{
    "success": true,
    "queue_size": 3,
    "active_requests": 5,
    "completed_requests": 12,
    "currently_processing": "550e8400-e29b-41d4-a716-446655440000",
    "worker_running": true
}
```

#### Request States
- `queued` - Request accepted and waiting in queue
- `processing` - Currently being executed  
- `completed` - Successfully completed
- `failed` - Execution failed
- `expired` - Request timed out before processing

#### Queue Configuration
The queue system can be configured in your service configuration:
```yaml
queue_max_size: 100          # Maximum queued requests
request_timeout: 300         # Request timeout (5 minutes)
result_retention: 3600       # Result retention (1 hour)
```

#### Rate Limiting
- **Default limits**: 60/minute, 600/hour, 6000/day
- **Example**: Setting `"20/minute"` effectively provides ~20 requests per minute across all endpoints

#### Error Responses

**Client Errors (4xx):**
- **400 Bad Request**: Invalid request format, missing required fields, or malformed JSON
- **401 Unauthorized**: Missing, invalid, or expired API key; no active session
- **403 Forbidden**: IP not allowed, access denied, or command not in allowed list
- **404 Not Found**: Request ID not found
- **429 Too Many Requests**: Rate limit exceeded

**Server Errors (5xx):**
- **500 Internal Server Error**: Command execution failed or unexpected server error
- **503 Service Unavailable**: Queue is full or service temporarily unavailable

### File Input Parameters (FILEDATA)

Commands requiring file input can use the `FILEDATA` placeholder with JSON content sent in the `filedata` field.

**Supported Commands:**
- **PAM Project Import**: `pam project import --filename=FILEDATA`
- **Import**: `import FILEDATA --format=json`
- **Enterprise Push**: `enterprise-push FILEDATA --email [userID or user mail]`

**Example:**
```bash
curl -X POST 'http://localhost:<port>/api/v1/executecommand' \
--header 'Content-Type: application/json' \
--header 'api-key: <your-api-key>' \
--data '{
  "command": "import FILEDATA --format=json",
  "filedata": {
    "records": [{"title": "My Website", "login": "user@example.com", "password": "MyPassword123!"}]
  }
}'
```

- Automatic temporary file creation and cleanup
- Sensitive data automatically masked in logs

### Base64-Encoded Configuration (credential-provision)

The `credential-provision` command supports base64-encoded YAML configuration via the `--config-base64` argument. This is useful when calling from external systems (ServiceNow, Aquera, Workday, etc.) where file paths aren't accessible on the Commander server.

**Encoding your YAML configuration:**
```bash
# Linux/macOS
base64 < employee.yaml
# Output: dXNlcjoKICBmaXJzdF9uYW1lOiAiSm9obiIK...

# Windows PowerShell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("employee.yaml"))

# Python
python3 -c "import base64; print(base64.b64encode(open('employee.yaml', 'rb').read()).decode())"
```

**API Request Example:**
```bash
curl -X POST 'http://localhost:<port>/api/v2/executecommand-async' \
--header 'Content-Type: application/json' \
--header 'api-key: <your-api-key>' \
--data '{
  "command": "credential-provision --config-base64 dXNlcjoKICBmaXJzdF9uYW1lOiAiSm9obiIK..."
}'
```

**With dry-run validation:**
```bash
curl -X POST 'http://localhost:<port>/api/v2/executecommand-async' \
--header 'Content-Type: application/json' \
--header 'api-key: <your-api-key>' \
--data '{
  "command": "credential-provision --config-base64 dXNlcjoKICBmaXJzdF9uYW1lOiAiSm9obiIK... --dry-run --output json"
}'
```

**Notes:**
- Uses standard RFC 4648 base64 encoding
- The `--config-base64` argument is mutually exclusive with `--config` (file path)
- Maximum size depends on HTTP request limits (typically works for configs up to ~100KB)

## Configuration

The service configuration is stored as an attachment to a vault record in JSON/YAML format and includes:

- **Service Title**: Identifier for the service configuration
- **Port Number**: Port for the API server
- **Run Mode**: Service execution mode (foreground/background)
- **Ngrok Configuration** (optional):
  - Ngrok tunneling enabled/disabled
  - Ngrok authentication token
  - Ngrok custom domain
  - Generated public URL
- **Cloudflare Configuration** (optional):
  - Cloudflare tunneling enabled/disabled
  - Cloudflare tunnel token
  - Cloudflare custom domain
  - Generated public URL
- **TLS Certificate Configuration** (optional):
  - TLS certificate enabled/disabled
  - Certificate file path
  - Certificate password
- **Advanced Security Settings**:
  - Rate limiting rules
  - IP allowed list (whitelist)
  - IP denied list (blacklist)
  - Encryption enabled/disabled
  - Encryption private key
- **API Configuration**:
  - API key(s) (Auto generated)
  - Command access controls
  - Token expiration settings
- **File Format**: Configuration storage format (JSON/YAML)

## Security Considerations

- All API requests require successful authentication via API key
- Rate limiting is enforced to prevent attacks
- IP-based access control can be configured
- Token expiration can be set for temporary access
- AES-256 (CBC) encryption for sensitive response data (optional)

## Logging

The service includes a comprehensive logging system that tracks:
- Service startup/shutdown events
- Configuration changes
- Command execution
- Security events
- Error conditions

### Background Process Logging
When running in **background mode**, service logs are stored in:
- **Location**: `keepercommander/service/core/logs/service_subprocess.log`
- **Content**: Subprocess output, errors, and service events
- **Auto-created**: Log directory is automatically created when service starts in background

### Ngrok Logging
When ngrok tunneling is enabled, additional logs are maintained:
- **Location**: `keepercommander/service/core/logs/ngrok_subprocess.log`
- **Content**: Ngrok tunnel startup, connection events, public URL generation, and tunnel errors
- **Includes**: Tunnel establishment, reconnection attempts, and ngrok-specific error messages
- **Auto-created**: Created automatically when ngrok tunneling is configured and service starts

### Cloudflare Logging
When Cloudflare tunneling is enabled, additional logs are maintained:
- **Location**: `keepercommander/service/core/logs/cloudflare_tunnel_subprocess.log`
- **Content**: Cloudflare tunnel startup, connection events, public URL generation, and tunnel errors
- **Includes**: Tunnel establishment, connection timeout detection, and firewall blocking diagnostics
- **Auto-created**: Created automatically when Cloudflare tunneling is configured and service starts

### General Logging Configuration
- **Configuration file**: `~/.keeper/logging_config.yaml` (auto-generated)
- **Default level**: `INFO`
- **Available levels**: INFO, DEBUG, ERROR, CRITICAL
- **Control**: Enable/disable logging by setting `enabled: false` in config file

## Error Handling

The service includes robust error handling for:
- Invalid configurations
- Authentication failures
- Rate limit violations
- Invalid commands

## Requirements

- Python 3.6+
- Keeper Commander
- Flask
- Dependencies listed in `requirements.txt`

## Docker Deploy

The Docker container provides a streamlined way to deploy Keeper Commander Service with automatic device registration and persistent login setup.

### Prerequisites

1. Install [Docker](https://www.docker.com/)

### Pull Docker Image

Pull the latest Docker image from Docker Hub:
```bash
docker pull keeper/commander:latest
```

Verify the image was pulled:
```bash
docker images | grep keeper/commander
```

### Authentication Methods

The Docker container supports four authentication methods:

#### Method 1: Using KSM Config File
Use Keeper Secrets Manager (KSM) config file to download the `config.json` configuration from a Keeper record. The container will:
- Download the `config.json` attachment from the specified record using the mounted KSM config file
- Use the downloaded config for authentication

**Two approaches available:**
- **Approach A - KSM Config Base64**: Pass the KSM config base64-encoded string (ideal for container orchestration)
- **Approach B - KSM Config File Mounting**: Mount the `ksm-config.json` file to the container

#### Method 2: Using KSM Token
Use a KSM one-time access token to download the `config.json` configuration from a Keeper record. The container will:
- Download the `config.json` attachment from the specified record using the provided KSM token
- Use the downloaded config for authentication

#### Method 3: Using Credentials (Recommended for new deployments)
Pass credentials directly via command line arguments. The container will automatically:
- Register the device with Keeper
- Enable persistent login
- Start the service

#### Method 4: Using Config File (For existing configurations)
Mount an existing Keeper configuration file to the container.


### Common Setup Steps for Config File Preparation

For authentication methods that require uploading a `config.json` file to your vault (KSM Config File, KSM Token, and Config File authentication), follow these steps on your host machine:

1. **Login to Keeper on your host machine:**
   ```bash
   keeper shell
   # Then login with your credentials
   login user@example.com
   ```

2. **Register device:**
   ```bash
   this-device register
   ```

3. **Enable persistent login:**
   ```bash
   this-device persistent-login on
   ```

4. **Set timeout:**
   ```bash
   this-device timeout 43200
   ```

5. **Upload config file:**
   Once configured, locate the `config.json` file in the `.keeper` directory on your host machine. Upload this file as an attachment to a record within a shared folder in your vault.

6. **Remove the original config file:**
   After uploading, delete the `config.json` file from the `.keeper` directory on your host machine to prevent duplicate configurations with the same device token/clone code.

### Run Docker Container

#### **With KSM Config File Authentication**

##### **Approach A: Using Base64-Encoded KSM Config** 

For environments where mounting files is not practical (e.g., container orchestration platforms), you can pass the KSM configuration as a base64-encoded string:

**Prerequisites:**

Before using KSM config file authentication, you must:

1. **Create a KSM Application** in your Keeper vault
2. **Generate a KSM config base64 value**
3. **Create a Keeper record** containing your service `config.json` as an attachment
4. **Share the record** with your KSM application

**Setup Steps:**

Complete the [Common Setup Steps for Config File Preparation](#common-setup-steps-for-config-file-preparation), then:

1. **Create KSM Configuration File:**
   - Go to Vault → Secrets Manager → My Applications.
   - Create new application and provide access to your shared folder.
   - Select your application, go to `Devices`, and click on `Add Device`.
   - Use `Configuration File` method and select `Base64` as configuration type.
   - Copy the KSM config base64-encoded string and keep it stored securely for future use.

**Run Container:**
```bash
docker run -d -p <port>:<port> \
  keeper/commander:latest \
  service-create -p <port> -c '<commands>' -f <json-or-yaml> \
  --ksm-config <BASE64_ENCODED_CONFIG> \
  --record <RECORD_UID_OR_TITLE>
```

**Example:**
```bash
docker run -d -p 9007:9007 \
  keeper/commander:latest \
  service-create -p 9007 -c 'ls,tree' -f json \
  --ksm-config eyJhcHBsaWNhdGlvbiI6ICJ0ZXN0LWFwcCIsICJjbGllbnRJZCI6ICJ0ZXN0LWNsaWVudC1pZCJ9 \
  --record ABC123-DEF456-GHI789
```

**Note:** The `--record` parameter supports both **record UID** and **record title**. If multiple records exist with the same title, you must use the specific UID instead.

##### **Approach B: Mounting KSM Config File Inside the Container**

**Prerequisites:**

Before using KSM config file authentication, you must:

1. **Create a KSM Application** in your Keeper vault
2. **Generate a KSM config file** (`ksm-config.json`)
3. **Create a Keeper record** containing your service `config.json` as an attachment
4. **Share the record** with your KSM application

**Setup Steps:**

Complete the [Common Setup Steps for Config File Preparation](#common-setup-steps-for-config-file-preparation), then:

1. **Create KSM Configuration File:**
   - Go to Vault → Secrets Manager → My Applications.
   - Create new application and provide access to your shared folder.
   - Select your application, go to `Devices`, and click on `Add Device`.
   - Use `Configuration File` method and download the JSON file.
   - Rename the downloaded file to `ksm-config.json` to avoid any conflict with `.keeper/config.json`.

**Run Container:**
```bash
docker run -d -p <port>:<port> \
  -v /path/to/local/ksm-config.json:/home/commander/ksm-config.json \
  keeper/commander:latest \
  service-create -p <port> -c '<commands>' -f <json-or-yaml> \
  --ksm-config /home/commander/ksm-config.json \
  --record <RECORD_UID_OR_TITLE>
```

**Example:**
```bash
docker run -d -p 9007:9007 \
  -v /path/to/local/ksm-config.json:/home/commander/ksm-config.json \
  keeper/commander:latest \
  service-create -p 9007 -c 'ls,tree' -f json \
  --ksm-config /home/commander/ksm-config.json \
  --record ABC123-DEF456-GHI789
```

**Note:** The `--record` parameter supports both **record UID** and **record title**. If multiple records exist with the same title, you must use the specific UID instead.

#### **With KSM Token Authentication**

**Prerequisites:**

Before using KSM Token authentication, you must:

1. **Create a KSM Application** in your Keeper vault
2. **Store the generated access token securely**
3. **Create a Keeper record** containing your `config.json` as an attachment
4. **Share the record** with your KSM application

**Setup Steps:**

Complete the [Common Setup Steps for Config File Preparation](#common-setup-steps-for-config-file-preparation), then:

1. **Create KSM Access Token:**
   - Go to Vault → Secrets Manager → My Applications 
   - Create new application and provide access to your shared folder
   - Grant "Can Edit" permission and generate the access token
   - Store the generated access token securely

**Run Container:**
```bash
docker run -d -p <port>:<port> \
  keeper/commander:latest \
  service-create -p <port> -c '<commands>' -f <json-or-yaml> \
  --ksm-token <KSM_TOKEN> \
  --record <RECORD_UID_OR_TITLE>
```

**Example:**
```bash
docker run -d -p 9007:9007 \
  keeper/commander:latest \
  service-create -p 9007 -c 'ls,tree' -f json \
  --ksm-token US:odncsdcindsijiojijj32i3ij2iknm23 \
  --record ABC123-DEF456-GHI789
```

**Note:** The `--record` parameter supports both **record UID** and **record title**. If multiple records exist with the same title, you must use the specific UID instead.

#### **With User/Password Authentication**

```bash
docker run -d -p <port>:<port> keeper/commander:latest \
  service-create \
  -p <port> \
  -c '<comma-separated-commands>' \
  -f <json-or-yaml> \
  --user <keeper-username> \
  --password <keeper-password> \
  --server <keeper-server>
```

**Parameters:**
- `-p, --port`: Port number for the service
- `-c, --commands`: Comma-separated list of allowed commands
- `-f, --fileformat`: Configuration file format (json/yaml)
- `--user`: Keeper username for authentication
- `--password`: Keeper password for authentication  
- `--server`: Keeper server (optional, defaults to `keepersecurity.com`)

**Example:**
```bash
docker run -d -p 9009:9009 keeper/commander:latest \
  service-create \
  -p 9009 \
  -c 'tree,ls' \
  -f json \
  --user myuser@company.com \
  --password mypassword
```

#### **With Config File Authentication**

**Prerequisites:**

Before using config file authentication, you must first create a properly configured `config.json` file on your host machine.

**Setup Steps:**

Follow steps 1-4 from the [Common Setup Steps for Config File Preparation](#common-setup-steps-for-config-file-preparation), then:

1. **Copy config file:**
   Once configured, locate the `config.json` file in the `.keeper` directory on your host machine and copy the contents of the `config.json` file to your desired path (e.g., `/path/to/local/config.json`) for Docker mounting.

2. **Remove the original config file:**
   After copying, delete the `config.json` file from the `.keeper` directory on your host machine to prevent duplicate configurations with the same device token/clone code.

Mount your existing Keeper config file:
```bash
docker run -d -p <port>:<port> \
  -v /path/to/local/config.json:/home/commander/.keeper/config.json \
  keeper/commander:latest \
  service-create -p <port> -c '<commands>' -f <json-or-yaml>
```

### Verify Deployment

1. **Check container status:**
   ```bash
   docker ps
   ```

2. **View container logs:**
   ```bash
   docker logs <container-name-or-id>
   ```

3. **Get API key from logs:**
   Look for the API key in the container logs:
   ```
   Generated API key: <API-KEY>
   ```

4. **Follow logs in real-time:**
   ```bash
   docker logs -f <container-name-or-id>
   ```

### Container Architecture

- **Base Image**: `python:3.11-slim`
- **Working Directory**: `/commander`
- **Config Directory**: `/home/commander/.keeper/`
- **Entrypoint**: `docker-entrypoint.sh` with automatic authentication setup

### Execute Command Endpoint

   ```bash
   # Queue enabled (v2 - async)
   curl --location 'http://localhost:<port>/api/v2/executecommand-async' \
   --header 'Content-Type: application/json' \
   --header 'api-key: <your-api-key>' \
   --data '{
      "command": "<command>"
   }'
   
   # Queue disabled (v1 - direct)  
   curl --location 'http://localhost:<port>/api/v1/executecommand' \
   --header 'Content-Type: application/json' \
   --header 'api-key: <your-api-key>' \
   --data '{
      "command": "<command>"
   }'
   ```

## Contributing

Please refer to Keeper Commander's contribution guidelines while making changes to this module.

## License

This module is part of Keeper Commander and is subject to its license terms.

## Support

For support, please contact:
- Email: commander@keepersecurity.com
- Documentation: [Keeper Commander Documentation](https://docs.keeper.io/en/secrets-manager/commander-cli/overview)
