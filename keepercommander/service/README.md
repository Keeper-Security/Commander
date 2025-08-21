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
- Enable TLS Certificate (y/n)
  - TLS Certificate path 
  - TLS Certificate password
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
  My Vault> service-create -p <port> -f <json-or-yaml> -c 'tree,ls,search,record-add,mkdir' -rm <foreground-or-background> -crtf <certificate-file-path> -crtp <certificate-password-key-path> -aip <allowed-ip-list> -dip <denied-ip-list>
```

Configure the service streamlined with Ngrok:

```bash
  My Vault> service-create -p <port> -f <json-or-yaml> -c 'tree,record-add,audit-report' -ng <ngrok-token> -cd <ngrok_custom_domain> -rm <foreground-or-background> -aip <allowed-ip-list> -dip <denied-ip-list>
``` 

Parameters:
- `-p, --port`: Port number for the service
- `-c, --commands`: Comma-separated list of allowed commands
- `-ng, --ngrok`: Ngrok authentication token for public URL access
- `-cd, --ngrok_custom_domain`: Ngrok custom domain name
- `-f, --fileformat`: File format (json/yaml)
- `-crtf, --certfile`: Certificate file path
- `-crtp, --certpassword`: Certificate password
- `-rm, --run_mode`: Run mode (foreground/background)
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

### Request Queue System

The service uses an asynchronous request queue system that provides:
- **Sequential Processing**: Requests are processed one at a time in FIFO order
- **Request Tracking**: Each request receives a unique ID for status tracking
- **No Dropped Requests**: All requests are queued and processed
- **Result Retrieval**: Asynchronous result retrieval using request IDs

#### API Endpoints

**Submit Request:**
```bash
curl -X POST 'http://localhost:<port>/api/v1/executecommand' \
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
    "message": "Request queued successfully. Use /api/v1/status/<request_id> to check progress, /api/v1/result/<request_id> to get results, or /api/v1/queue/status for queue info."
}
```

**Check Request Status:**
```bash
curl 'http://localhost:<port>/api/v1/status/<request_id>' \
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
curl 'http://localhost:<port>/api/v1/result/<request_id>' \
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
curl 'http://localhost:<port>/api/v1/queue/status' \
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

#### Error Responses
- **503 Service Unavailable**: Queue is full
- **404 Not Found**: Request ID not found
- **500 Internal Server Error**: Command execution failed

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

### General Logging Configuration
- **Configuration file**: `~/.keeper/logging_config.yaml` (auto-generated)
- **Default level**: `INFO`
- **Available levels**: INFO, DEBUG, ERROR, CRITICAL
- **Control**: Enable/disable logging by setting `enabled: false` in config file

## Requirements

- Python 3.6+
- Keeper Commander
- Flask
- Dependencies listed in `requirements.txt`

## Error Handling

The service includes robust error handling for:
- Invalid configurations
- Authentication failures
- Rate limit violations
- Invalid commands

## Docker Deploy

### Install, build and run docker image
 
  1. Install [Docker](https://www.docker.com/).
  1. Clone the repository [git clone](https://github.com/Keeper-Security/Commander.git).
  1. Build docker image using command  ``` docker build -t keeper-commander . ```
  1. Verify docker image created. ``` docker images ```
  1. Set two environment variables in your terminal window:
      1. `KEEPER_USERNAME` - This is the username that can login to Keeper Commander
      1. `KEEPER_PASSWORD` - This is the password for the above user
  1. Run the keeper-commander docker image with ngrok using command
      ```bash
        docker run -d -p <port>:<port> keeper-commander \
          service-create -p <port> -c '<comma separated commands like tree,ls>' \
          -aip <allowed-ip-list-comma seprated>
          -dip <denied-ip-list-comma seprated>
          -ng <ngrok-auth-token>
          -cd <ngrok-custom-domain>
          --user $KEEPER_USERNAME \
          --password $KEEPER_PASSWORD
      ```  
   1. Verify keeper-commander image is started using command  `docker ps`
   1. Check the logs using command
      ```bash
       docker logs <docker container name or ID>
       ```
      and get the API key from logs. The API key will show up like this:
      ```
      Generated API key: <API-KEY>
      ```

### Execute Command Endpoint

   ```bash
   curl --location 'http://localhost:<port>/api/v1/executecommand' \
   --header 'Content-Type: application/json' \
   --header 'api-key: <your-api-key>' \
   --data '{
      "command": "<command>"
   }'
   ```
## Logging configuration
  Once service mode started the `logging_config.yaml` is generated at default path(~\.keeper) with default level `INFO`
  User can disable logging by setting `enabled:false` or can change log level(INFO,DEBUG,ERROR,CRITICAL) using `logging_config.yaml`
  ```bash
    logging:
      enabled: true
      level: INFO
  ```
## Contributing

Please refer to Keeper Commander's contribution guidelines while making changes to this module.

## License

This module is part of Keeper Commander and is subject to its license terms.

## Support

For support, please contact:
- Email: commander@keepersecurity.com
- Documentation: [Keeper Commander Documentation](https://docs.keeper.io/en/secrets-manager/commander-cli/overview)
