# Keeper Commander MCP Server

## Overview

The Keeper Commander MCP (Model Context Protocol) server enables AI agents like Claude to interact with your Keeper vault. It exposes Keeper Commander functionality through the standardized MCP protocol, allowing AI assistants to help you manage passwords, search your vault, and perform vault operations.

**⚠️ ALPHA RELEASE WARNING**: This is an alpha feature. By using this server, you acknowledge that your vault data will be accessible to AI/LLM systems. Use at your own risk and ensure you understand the security implications.

## Features

- **Secure by Default**: All commands disabled by default, explicit opt-in required
- **Security Confirmation**: Requires explicit user confirmation before starting server
- **Command Filtering**: Only AI-appropriate commands are exposed
- **Permission-Based Access**: Enterprise/MSP commands require appropriate permissions
- **Granular Permissions**: Control exactly which commands AI agents can access
- **Interactive Permission Management**: Easy-to-use interface for setting permissions
- **AI-Friendly Output**: Automatic JSON formatting with error correction
- **Session Management**: Stateful operations with isolated sessions per connection
- **Rate Limiting**: Protect against abuse with configurable rate limits
- **Remote Access**: WebSocket support for remote AI clients (with TLS)

## What's New

### Latest Features
- **Alpha Security Warnings**: Comprehensive warnings about AI data exposure
- **Command Appropriateness Filtering**: Only safe commands exposed to AI
- **Permission-Based Command Access**: Enterprise/MSP commands require permissions
- **JSON Output Auto-Repair**: Fixes malformed JSON from enterprise commands
- **Dual-Mode Permission Interface**: Terminal and simple modes for different environments
- **Log Rotation**: Configurable size/time-based log rotation
- **Remote WebSocket Access**: Secure remote connections with TLS support

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Keeper Commander account
- Virtual environment (recommended)

### Installation

1. **Clone and set up the repository**:
```bash
git clone https://github.com/Keeper-Security/Commander.git commander-mcp-server
cd commander-mcp-server
git checkout feature/mcp-server
```

2. **Create and activate virtual environment**:
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install with MCP support**:
```bash
# Use the venv's pip directly
.venv/bin/pip install -e .
```

### First Time Setup

1. **Login to Keeper Commander**:
```bash
.venv/bin/keeper login
```
Enter your Keeper credentials when prompted.

2. **Enable MCP server**:
```bash
.venv/bin/keeper mcp-server config --enable
```

3. **Allow some commands**:
```bash
# Start with safe read-only commands
.venv/bin/keeper mcp-server permissions --add whoami
.venv/bin/keeper mcp-server permissions --add list
.venv/bin/keeper mcp-server permissions --add search
.venv/bin/keeper mcp-server permissions --add get
.venv/bin/keeper mcp-server permissions --add tree
.venv/bin/keeper mcp-server permissions --add generate

# Check what's allowed
.venv/bin/keeper mcp-server permissions --show
```

4. **Start the MCP server**:
```bash
.venv/bin/keeper mcp-server start
```

When starting, you'll see a security review of your current settings and must confirm with "yes" to proceed:
```
MCP Server Security Review
==================================================
WARNING: Starting MCP server will expose Keeper commands to AI agents.

Current Configuration:

Allowed Commands (3):
  - list
  - search
  - whoami

Rate Limit: 60 requests/minute

Transport: stdio (local only)

==================================================
Do you want to start the MCP server with these settings? (yes/no): 
```

To skip the confirmation (for scripts or testing):
```bash
.venv/bin/keeper mcp-server start --no-confirm
```

## Remote Access (New!)

The MCP server now supports remote access via WebSocket, allowing AI clients to connect over the network.

### Setting Up Remote Access

1. **Enable remote access**:
```bash
.venv/bin/keeper mcp-server remote enable --port 3001
```

2. **Generate authentication token**:
```bash
.venv/bin/keeper mcp-server remote token generate claude-desktop
```
Save the generated token securely - it won't be shown again!

3. **(Optional) Enable TLS for secure connections**:
```bash
# Create directory for certificates
mkdir -p ~/.keeper/mcp-certs
cd ~/.keeper/mcp-certs

# Generate private key
openssl genrsa -out mcp-server.key 2048

# Generate self-signed certificate (valid for 1 year)
openssl req -new -x509 -key mcp-server.key -out mcp-server.crt -days 365 \
  -subj "/C=US/ST=State/L=City/O=Keeper MCP/CN=localhost"

# Set secure permissions on private key
chmod 600 mcp-server.key

# Update your config.json to enable TLS:
# "mcp": {
#   "remote_access": {
#     "tls": {
#       "enabled": true,
#       "cert_file": "~/.keeper/mcp-certs/mcp-server.crt",
#       "key_file": "~/.keeper/mcp-certs/mcp-server.key"
#     }
#   }
# }
```

4. **Start the remote server**:
```bash
.venv/bin/keeper mcp-server remote start
```

### Remote Commands

- `mcp-server remote status` - Show remote access configuration
- `mcp-server remote enable/disable` - Toggle remote access
- `mcp-server remote token generate <name>` - Create auth token
- `mcp-server remote token list` - List all tokens (masked)
- `mcp-server remote token revoke <name>` - Revoke a token
- `mcp-server remote start` - Start WebSocket server

### Security Notes

- Remote access is **disabled by default**
- **Authentication required** - No anonymous connections
- **TLS recommended** - Warning shown if not using encryption
- **Token security** - Tokens are shown once, store them securely
- All remote connections are logged

## Usage with AI Clients

### Claude Desktop Integration

You can connect to the MCP server in two ways:

#### Option 1: Local Connection (stdio)
Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "keeper": {
      "command": "/path/to/commander-mcp-server/.venv/bin/keeper",
      "args": ["mcp-server", "start", "--no-confirm"],
      "env": {
        "KEEPER_CONFIG_FILE": "/path/to/your/config.json"
      }
    }
  }
}
```

#### Option 2: Remote Connection (WebSocket)
For connecting to a remote MCP server:
```json
{
  "mcpServers": {
    "keeper-remote": {
      "url": "ws://localhost:3001",
      "auth": {
        "token": "YOUR_AUTH_TOKEN_HERE"
      }
    }
  }
}
```

For TLS connections, use `wss://` instead of `ws://`.

2. Restart Claude Desktop. You should now see Keeper tools available in the interface.

**Note**: When running through Claude Desktop, the security confirmation is automatically skipped since the MCP server runs in non-interactive mode. Make sure to configure your permissions carefully before connecting through Claude Desktop.

### Available Commands

The MCP server exposes **128 commands** across different categories:
- **89 Regular commands** - Vault operations, password management, etc.
- **28 Enterprise commands** - Team management, compliance, auditing
- **11 MSP commands** - Managed Service Provider operations

Use `keeper mcp-server permissions --list` to see all available commands. Here are some commonly used ones:

#### Read Operations (Safe)
- `whoami` - Display current user information
- `list` - List all records
- `search` - Search vault with patterns
- `get` - Get record/folder details
- `tree` - Display folder structure
- `list-sf` - List shared folders
- `list-team` - List teams

#### Password Management
- `generate` - Generate secure passwords
- `password-report` - Analyze password strength

#### Write Operations (Use Carefully)
- `record-add` - Add new records
- `record-update` - Update existing records
- `mkdir` - Create folders
- `mv` - Move items
- `append-notes` - Add notes to records

#### Security & Compliance
- `security-audit` - Run security audit
- `breachwatch` - Check for breached passwords

#### Enterprise Operations
- `enterprise-info` - Display enterprise tree structure
- `enterprise-user` - Manage enterprise users
- `enterprise-team` - Manage enterprise teams
- `enterprise-role` - Manage enterprise roles
- `audit-log` - Export enterprise audit log
- `compliance` - Compliance reporting

#### MSP Operations
- `msp-info` - Display MSP details
- `msp-add` - Add managed company
- `msp-update` - Modify managed company license
- `switch-to-mc` - Switch context to managed company

### Command Examples

Once connected through an AI client, you can ask things like:

- "Show me all my passwords"
- "Search for records containing 'email'"
- "Generate a secure password with 20 characters"
- "Show me the folder structure of my vault"
- "Check if any of my passwords have been breached"
- "Get the details of my GitHub record"

## Configuration

### Configuration File

MCP settings are stored in your Keeper config file (typically `~/.keeper/config.json`):

```json
{
  "user": "your-email@example.com",
  "server": "keepersecurity.com",
  "mcp": {
    "enabled": true,
    "permissions": {
      "allowed_commands": ["whoami", "list", "search", "get"],
      "deny_patterns": ["login", "*2fa*", "accept", "decline"],
      "rate_limit": {
        "requests_per_minute": 60,
        "burst": 10
      }
    },
    "logging": {
      "enabled": true,
      "level": "info",
      "file": "mcp-server.log"
    },
    "session_timeout": 30,
    "remote_access": {
      "enabled": false,
      "port": 3001,
      "auth_tokens": []
    }
  }
}
```

### Configuration Options

- **enabled**: Enable/disable MCP server
- **allowed_commands**: List of commands AI can execute
- **deny_patterns**: Glob patterns for commands to always deny
- **rate_limit**: Rate limiting configuration
- **logging**: Logging settings with rotation support
- **session_timeout**: Session timeout in minutes
- **remote_access**: Remote access settings

### Configuration Commands

```bash
# Enable MCP server
.venv/bin/keeper mcp-server config --enable

# Disable MCP server
.venv/bin/keeper mcp-server config --disable

# Set rate limit
.venv/bin/keeper mcp-server config --rate-limit 120

# Set remote port (for future use)
.venv/bin/keeper mcp-server config --remote-port 3002

# Show current configuration
.venv/bin/keeper mcp-server config --show
```

### Managing Permissions

#### Basic Permission Management
```bash
# List all available commands with categories
.venv/bin/keeper mcp-server permissions --list

# Add a command
.venv/bin/keeper mcp-server permissions --add record-add

# Remove a command
.venv/bin/keeper mcp-server permissions --remove rm

# Add deny pattern
.venv/bin/keeper mcp-server permissions --add-deny "*delete*"

# Show current permissions
.venv/bin/keeper mcp-server permissions --show
```

#### Interactive Permission Mode
Use the interactive mode for managing permissions:
```bash
.venv/bin/keeper mcp-server permissions --interactive
```

Interactive mode features two interfaces:

**1. Terminal Mode (when running outside Keeper shell):**
- **Arrow key navigation** - Use ↑/↓ to move through commands
- **Scrollable interface** - Automatically scrolls when you reach edges
- **Page Up/Down** - Jump through pages quickly
- **Space to toggle** - Press SPACE to allow/deny a command
- **Visual indicators** - Shows ✓ for allowed commands
- **Real-time updates** - See changes instantly
- **Clear display** - Full-screen interface with status info

**2. Simple Mode (when running inside Keeper shell):**
- **Numbered list** of all available commands
- **Simple input** - Type command number to toggle permission
- **Page navigation** - 'n' for next page, 'p' for previous
- **Bulk operations** - 'a' to allow all, 'c' to clear all
- **Save or quit** - 's' to save changes, 'q' to cancel

**Controls:**
- Terminal Mode: Arrow keys, SPACE to toggle, ENTER to save, Q to quit
- Simple Mode: Number input, n/p for navigation, s to save, q to quit

Example displays:

**Terminal Mode (outside Keeper shell):**
```
Interactive Permission Mode
Arrow keys: Navigate | SPACE: Toggle | ENTER: Save | Q: Quit
Currently allowed: 3 commands

↑ 5 more above ↑
  [ ] clipboard-copy              Retrieve the password for a specific recor...
  [ ] connect                     Establishes connection to external server.
  [ ] convert                     Convert record(s) to use record types
▶ [✓] list                        List all records
  [✓] search                      Search the vault. Can use a regular expres...
  [ ] get                         Get record/folder details
  [ ] tree                        Display folder structure
  [✓] whoami                      Display current user information
  [ ] record-add                  Add new records
  [ ] record-update               Update existing records
  [ ] mkdir                       Create folders
  [ ] mv                          Move items
  [ ] append-notes                Append notes to an existing record.
  [ ] security-audit              Run security audit
↓ 74 more below ↓

Commands: 19/128 | Allowed: 3
```

**Simple Mode (inside Keeper shell):**
```
Interactive Permission Mode
Note: Running in simple mode. For better experience, run outside the Keeper shell.

Available Commands:
Currently allowed: list, search, whoami

Commands 1-20 of 128:
  1. [ ] 2fa                         2FA management
  2. [ ] accept-transfer             Accept account transfer
  3. [ ] add                         Add record
  4. [✓] list                        List all records
  5. [✓] search                      Search the vault. Can use a regular expres...
  6. [ ] get                         Get record/folder details
  7. [✓] whoami                      Display current user information
  ...

Options:
  Enter command number to toggle permission
  'n' - Next page
  'p' - Previous page
  'a' - Allow all commands
  'c' - Clear all permissions
  's' - Save and exit
  'q' - Quit without saving

Choice: 
```

#### Bulk Permission Operations
```bash
# Enable all non-interactive commands (use with caution!)
.venv/bin/keeper mcp-server permissions --enable-all

# Disable all commands
.venv/bin/keeper mcp-server permissions --disable-all

# Enable safe read-only commands
.venv/bin/keeper mcp-server permissions --enable-safe
```

The `--enable-safe` option enables these read-only commands:
- `whoami`, `list`, `search`, `get`, `tree`, `cd`, `pwd`
- `list-sf`, `list-team`, `list-user`, `list-group`
- `security-audit`, `password-report`, `record-history`
- `version`, `help`, `shell`, `history`

## Security Best Practices

1. **Start with Minimal Permissions**: Only enable commands you need
2. **Use Read-Only Commands First**: Get comfortable before enabling writes
3. **Avoid Dangerous Commands**: Be careful with `rm`, `delete-all`, etc.
4. **Monitor Activity**: Check logs regularly
5. **Use Deny Patterns**: Block risky command patterns
6. **Rate Limiting**: Keep default rate limits or make them stricter
7. **Session Timeouts**: Use appropriate timeout values

## Monitoring and Debugging

### Log Rotation Configuration

The MCP server supports automatic log rotation to prevent log files from growing too large:

#### Size-based Rotation (Default)
```json
{
  "mcp": {
    "logging": {
      "enabled": true,
      "level": "info",
      "file": "~/.keeper/logs/mcp-server.log",
      "rotation": {
        "type": "size",
        "max_size_mb": 10,
        "backup_count": 5
      }
    }
  }
}
```

#### Time-based Rotation
```json
{
  "mcp": {
    "logging": {
      "enabled": true,
      "level": "info", 
      "file": "~/.keeper/logs/mcp-server.log",
      "rotation": {
        "type": "time",
        "when": "midnight",
        "interval": 1,
        "backup_count": 7,
        "suffix": "%Y-%m-%d"
      }
    }
  }
}
```

**Rotation Options:**
- **type**: `"size"` (default) or `"time"`
- **For size-based rotation:**
  - **max_size_mb**: Maximum file size before rotation (default: 10MB)
  - **backup_count**: Number of backup files to keep (default: 5)
- **For time-based rotation:**
  - **when**: Rotation interval - `"midnight"`, `"H"` (hourly), `"D"` (daily), `"W0"`-`"W6"` (weekly)
  - **interval**: Interval multiplier (default: 1)
  - **backup_count**: Number of backup files to keep (default: 7)
  - **suffix**: Date format for rotated files (default: "%Y-%m-%d")

Rotated log files are automatically named with timestamps or sequence numbers.

### Check Server Status
```bash
.venv/bin/keeper mcp-server status
```

The status command shows:
- MCP SDK installation status
- Server enabled/disabled state
- Allowed commands and deny patterns
- Rate limit settings
- Remote access configuration
- Session timeout
- Logging settings

Example output:
```
MCP SDK Status: Installed

MCP Server Configuration
========================================
  Status: Enabled

  Permissions:
    Allowed Commands: whoami, list, search
    Deny Patterns: login, *2fa*

  Rate Limit: 60 req/min

  Remote Access:
    Disabled

  Session Timeout: 30 minutes

  Logging:
    Enabled
    Level: info
```

### View Logs
If logging is enabled, check the log file specified in your config (default: `mcp-server.log`)

### Test Commands Manually
Before allowing a command through MCP, test it manually:
```bash
.venv/bin/keeper <command> <arguments>
```

## How MCP Clients See Commands

When connected through MCP, AI clients receive detailed information about each command:

### Tool Information
Each Keeper command is exposed as an MCP tool with:
- **Tool Name**: Prefixed with `keeper_` (e.g., `keeper_search`, `keeper_list`)
- **Description**: Command description with aliases (e.g., "Search the vault. Can use a regular expression. (aliases: s)")
- **Input Schema**: Complete JSON schema describing all parameters

### Example Tool Schema
Here's what Claude sees for the search command:
```json
{
  "name": "keeper_search",
  "description": "Search the vault. Can use a regular expression. (aliases: s)",
  "inputSchema": {
    "type": "object",
    "properties": {
      "pattern": {
        "description": "search pattern",
        "type": "string"
      },
      "verbose": {
        "description": "verbose output",
        "type": "boolean"
      },
      "categories": {
        "description": "One or more of these letters for categories to search: \"r\" = records, \"s\" = shared folders, \"t\" = teams",
        "type": "string"
      }
    },
    "required": []
  }
}
```

This allows AI clients to:
- Understand what parameters each command accepts
- Know the type of each parameter (string, boolean, array, etc.)
- See which parameters are required vs optional
- View enum values for choice parameters
- Read helpful descriptions for each parameter

## Troubleshooting

### JSON Parsing Errors

If you see errors like:
```
SyntaxError: Unexpected token 'P', "{"role":PAM Admins"... is not valid JSON
```

This is usually caused by commands that output mixed text/JSON format (particularly enterprise commands showing role enforcements). The MCP server now includes several protections:

1. **Automatic JSON format**: Enterprise commands automatically use `--format json` when called through MCP
2. **Content filtering**: Problematic sections (like role enforcements with embedded JSON) are filtered out
3. **JSON repair**: The formatter attempts to fix common JSON issues like unquoted values

If you continue to see these errors:
1. Check which command is causing the issue
2. Ensure the command is in the allowed list
3. Report the issue with the specific command and output

### Finding MCP Logs

MCP logs can be found in multiple locations:

1. **Keeper MCP Server Logs** (if logging is enabled in config):
   ```bash
   # Default location (check your config.json)
   tail -f mcp-server.log
   
   # Or check your config for the log file location
   cat ~/.keeper/config.json | grep -A 3 "logging"
   ```

2. **Claude Desktop Logs**:
   - **macOS**: `~/Library/Logs/Claude/mcp-server-keeper.log`
   - **Windows**: `%APPDATA%\Claude\logs\mcp-server-keeper.log`
   - **Linux**: `~/.config/Claude/logs/mcp-server-keeper.log`

3. **Real-time MCP Server Output**:
   When running the server directly, you'll see logs in the terminal:
   ```bash
   .venv/bin/keeper mcp-server start
   ```

### Enabling Debug Logging

To get more detailed logs, update your Keeper config:

```json
{
  "mcp": {
    "logging": {
      "enabled": true,
      "level": "debug",
      "file": "mcp-server-debug.log"
    }
  }
}
```

Or set via environment variable when starting:
```bash
KEEPER_DEBUG=1 .venv/bin/keeper mcp-server start
```

### Claude Desktop Configuration Issues

Based on your screenshot, here are the common JSON errors and fixes:

1. **Fix your Claude Desktop config** (`~/Library/Application Support/Claude/claude_desktop_config.json`):
   ```json
   {
     "mcpServers": {
       "keeper": {
         "command": "/Users/mustinov/Source/commander-mcp-server/.venv/bin/keeper",
         "args": ["mcp-server", "start"],
         "env": {
           "KEEPER_CONFIG_FILE": "/Users/mustinov/.keeper/config.json"
         }
       }
     }
   }
   ```

2. **Common JSON errors to fix**:
   - Remove any trailing commas after the last item in objects/arrays
   - Ensure all strings are properly quoted
   - Make sure brackets and braces are balanced
   - Use forward slashes (/) in paths, not backslashes

3. **Validate your JSON**:
   ```bash
   # Check if the JSON is valid
   python3 -m json.tool ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

### MCP Server Won't Start
- Ensure you're logged in: `.venv/bin/keeper login`
- Check MCP is enabled: `.venv/bin/keeper mcp-server config --enable`
- Verify at least one command is allowed
- Check the logs (see above)

### Commands Not Working
- Check permissions: `.venv/bin/keeper mcp-server permissions --show`
- Verify command isn't in deny patterns
- Check rate limits haven't been exceeded
- Look for errors in logs

### Connection Issues
- Ensure server is running: `.venv/bin/keeper mcp-server start`
- Check the path in Claude Desktop config is correct
- Verify virtual environment path is absolute
- After fixing config, restart Claude Desktop completely

## Advanced Usage

### Custom Session Handling
The MCP server maintains sessions for stateful operations:
- Each AI connection gets its own session
- Sessions timeout after inactivity (default: 30 minutes)
- Stateful commands like `cd` work within sessions

### Output Formatting
The MCP server automatically formats output for AI consumption:
- Tables → Structured JSON with headers and rows
- Key-value pairs → JSON objects
- Lists → JSON arrays
- Errors → Structured error objects with details

### Rate Limiting
Protect your vault from abuse:
- Global rate limit (default: 60 requests/minute)
- Per-command rate limits (configurable)
- Burst allowance for short spikes

## Development

### Running Tests
```bash
# Component tests
.venv/bin/python test_mcp_components.py

# Client test
.venv/bin/python test_mcp_client.py
```

### Architecture
- `keepercommander/mcp/` - MCP server implementation
- `keepercommander/commands/mcp_commands.py` - CLI commands
- See `MCP_SERVER_PRD.md` for detailed architecture

## Support

- Keeper Commander Documentation: https://docs.keeper.io/
- MCP Protocol: https://modelcontextprotocol.io/
- Issues: https://github.com/Keeper-Security/Commander/issues

## License

Keeper Commander is licensed under the MIT License. See LICENSE file for details.