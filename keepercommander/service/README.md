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
  - TLS Certficate path 
  - TLS Certficate password
- Advance Security (y/n)
  - Ralte Limit
  - Allowed IP List (comma-separated)
  - Denied IP List (comma-separated)
  - Enable Encryption (y/n) 
- List of supported commands (comma separated)
- Toekn Expiration Time(Xm, Xh, Xd) or empty for no expiration
- File format (yaml/json)

### Streamlined Configuration

Configure the service with a streamline with TLS:

```bash
  My Vault> service-create -p <port> -f <json-Or-yaml> -c 'tree,ls,search,record-add,mkdir' -rm <foreground-Or-background> -crtf <certificate-file-path> -crtp <certificate-password-key-path>  -aip <allwed-Ip-list> -dip <denied-Ip-list>
```

Configure the service with a streamline wiht Ngrok:

```bash
  My Vault> service-create -p <port> -f <json-Or-yaml> -c 'tree,record-add,audit-report' -ng <ngrok-token> -cd <ngrok_custom_domain> -rm <foreground-Or-background> -aip <allwed-Ip-list> -dip <denied-Ip-list>
``` 

Parameters:
- `-p, --port`: Port number for the service
- `-c, --commands`: Comma-separated list of allowed commands
- `-ng, --ngrok`: Ngrok authentication token for public URL access
- `-cd, --ngrok_custom_domain`: Ngrok custom domain name
- `-f, --fileformat`: File Format.
- `-crtf, --certfile`: Certificate file path.
- `-crtp, --certpassword`: Certificate key path.
- `-rm, --run_mode`: Mode of process (forground/background)
- `-dip, --deniedip`: Denied ip list to access service
- `-aip, --allowedip'`: Allowed ip list to access service

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

### Execute Command Endpoint

```bash
curl --location 'http://localhost:<port>/api/v1/executecommand' \
--header 'Content-Type: application/json' \
--header 'api-key: <your-api-key>' \
--data '{
    "command": "tree"
}'
```

## Configuration

The service configuration is stored as an attachment to a vault record in JSON/YAML format and includes:

- Port Number
- Ngrok configuration (optional)
- TLS certificate path (optional)
- Security settings
  - Rate limiting rules
  - IP restrictions
  - Encryption settings
  - Token expiration
- API key(s) (Auto generated)
- Command access controls

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
