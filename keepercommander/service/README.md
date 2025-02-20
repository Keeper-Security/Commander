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

## Installation

### Prerequisites
- Python 3.6 or higher
- Git
- pip (Python package installer)

### Step-by-Step Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/metron-labs/keeper-commander.git
   cd keeper-commander
   ```

2. **Create and Activate Virtual Environment**
   ```bash
   # Create and activate virtual environment

   # On macOS/Linux:
   python3 -m venv venv
   source venv/bin/activate

   # On Windows:
   python -m venv venv
   venv\Scripts\activate  
   ```

3. **Install Dependencies**
   ```bash
   # Install in editable mode with all dependencies
   pip install -e .
   ```

4. **Verify Installation**
   ```bash
   # Start Keeper Commander
   keeper shell
   ```

   Indicators of successful integration:
   - Application starts without errors
   - Ability to log in with Keeper credentials
   - `service-status` command returns current service state

### Troubleshooting Installation
If you encounter any issues during installation, ensure:
- Python 3.6+ is installed and in your system PATH
- Virtual environment is activated (look for `(venv)` in terminal prompt)
- All dependencies are installed correctly (`pip list`)

## Usage

### Basic Setup

1. Start Keeper Commander:
   ```bash
   keeper shell
   ```

2. Log in with your Keeper credentials when prompted

### Interactive Configuration

Create and configure the service with interactive prompts:
```bash
My Vault> service-create
```

You'll be prompted to configure:
- Config format
- Port number
- Ngrok tunneling options
- Security settings
- Command access controls

### Streamlined Configuration

Configure the service with a single command:
```bash
My Vault> service-create -p 9090 -c 'tree,ls,search,record-add,mkdir' -ng <ngrok-token>
```

Parameters:
- `-p, --port`: Port number for the service
- `-c, --commands`: Comma-separated list of allowed commands
- `-ng, --ngrok`: Ngrok authentication token for public URL access

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

The service configuration is stored in JSON/YAML format and includes:

- Port settings
- Ngrok configuration (optional)
- Security settings
  - Rate limiting rules
  - IP restrictions
  - Encryption settings
  - Token expiration
- API key(s)
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

## Contributing

Please refer to Keeper Commander's contribution guidelines while making changes to this module.

## License

This module is part of Keeper Commander and is subject to its license terms.

## Support

For support, please contact:
- Email: commander@keepersecurity.com
- Documentation: [Keeper Commander Documentation](https://docs.keeper.io/en/secrets-manager/commander-cli/overview)